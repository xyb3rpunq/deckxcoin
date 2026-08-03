/**
 * Transaction memory pool.
 *
 * Holds transactions that are valid against the current tip but not yet mined.
 * Three jobs, in order of how easy they are to get wrong:
 *
 *   1. **Reject early.** A transaction that cannot apply to the current state
 *      never enters, so miners never waste a block template on it and peers
 *      never get it relayed onward.
 *   2. **Stay consistent across reorgs.** When blocks are disconnected their
 *      transactions come *back* into the pool; when blocks connect, the
 *      transactions they contain leave it. A mempool that ignores reorgs
 *      quietly serves double-spends.
 *   3. **Bound its own size.** An unbounded mempool is a free memory-exhaustion
 *      attack. Eviction is by fee rate, lowest first.
 *
 * Ordering for block templates is fee-rate descending — highest fee per byte
 * first — with dependencies respected: a child never appears before its parent.
 */

import { serializeTx, txid, type Transaction } from '../tx.ts';
import { applyTx } from '../chain.ts';
import type { WorldState } from '../state.ts';
import type { Hex } from '../crypto.ts';

export interface MempoolEntry {
  readonly tx: Transaction;
  readonly txid: Hex;
  readonly fee: bigint;
  readonly size: number;
  /** Zaps per byte, the number miners actually sort on. */
  readonly feeRate: number;
  readonly addedAt: number;
  /** Height of the tip when this entered. Used for expiry. */
  readonly addedAtHeight: number;
}

export interface MempoolOptions {
  /** Maximum entries retained. Beyond this, the cheapest are evicted. */
  readonly maxSize?: number;
  /** Minimum fee rate accepted, zaps per byte. */
  readonly minFeeRate?: number;
  /** Entries older than this many blocks are dropped. */
  readonly expiryBlocks?: number;
}

export interface AddResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly entry?: MempoolEntry;
  /** True when the pool already had it. Not an error — just not news. */
  readonly duplicate?: boolean;
}

export class Mempool {
  readonly #entries = new Map<Hex, MempoolEntry>();
  /** outpoint -> txid, so a conflicting spend is caught in O(1). */
  readonly #spent = new Map<string, Hex>();

  readonly maxSize: number;
  readonly minFeeRate: number;
  readonly expiryBlocks: number;

  constructor(opts: MempoolOptions = {}) {
    this.maxSize = opts.maxSize ?? 5_000;
    this.minFeeRate = opts.minFeeRate ?? 0;
    this.expiryBlocks = opts.expiryBlocks ?? 336; // ~2 days at 10-minute blocks
  }

  get size(): number {
    return this.#entries.size;
  }

  has(id: Hex): boolean {
    return this.#entries.has(id);
  }

  get(id: Hex): Transaction | undefined {
    return this.#entries.get(id)?.tx;
  }

  ids(): Hex[] {
    return [...this.#entries.keys()];
  }

  entries(): MempoolEntry[] {
    return [...this.#entries.values()];
  }

  /**
   * Validate against `state` and admit.
   *
   * `state` must be the world state of the current tip. Validation runs on a
   * clone, so a rejected transaction leaves nothing behind — and an accepted
   * one is *not* applied either: the pool holds candidates, not state.
   */
  add(tx: Transaction, state: WorldState, height: number, time: number): AddResult {
    const id = txid(tx);
    if (this.#entries.has(id)) return { ok: true, duplicate: true, entry: this.#entries.get(id) };

    if (tx.kind === 'coinbase') {
      return { ok: false, error: 'coinbase transactions are never relayed' };
    }

    // Conflict with something already pooled? First seen wins — replace-by-fee
    // is a policy decision with real downsides and is deliberately not here.
    for (const input of tx.inputs) {
      const key = `${input.txid}:${input.vout}`;
      const conflict = this.#spent.get(key);
      if (conflict && conflict !== id) {
        return { ok: false, error: `conflicts with pooled transaction ${conflict} over ${key}` };
      }
    }

    const draft = state.clone();
    const res = applyTx(tx, draft, { height: height + 1, time });
    if (!res.ok) return { ok: false, error: res.error };

    const size = serializeTx(tx, { withSignatures: true }).length;
    const feeRate = size > 0 ? Number(res.fee) / size : 0;
    if (feeRate < this.minFeeRate) {
      return { ok: false, error: `fee rate ${feeRate.toFixed(4)} is below the minimum ${this.minFeeRate}` };
    }

    const entry: MempoolEntry = {
      tx,
      txid: id,
      fee: res.fee,
      size,
      feeRate,
      addedAt: Date.now(),
      addedAtHeight: height,
    };

    this.#entries.set(id, entry);
    for (const input of tx.inputs) this.#spent.set(`${input.txid}:${input.vout}`, id);

    if (this.#entries.size > this.maxSize) this.#evictCheapest();
    return { ok: true, entry };
  }

  remove(id: Hex): boolean {
    const entry = this.#entries.get(id);
    if (!entry) return false;
    this.#entries.delete(id);
    for (const input of entry.tx.inputs) {
      const key = `${input.txid}:${input.vout}`;
      if (this.#spent.get(key) === id) this.#spent.delete(key);
    }
    return true;
  }

  clear(): void {
    this.#entries.clear();
    this.#spent.clear();
  }

  /* ──────────────────────────────────────────────────── chain events ── */

  /** Drop everything a newly connected block contains. */
  onBlockConnected(txs: readonly Transaction[]): number {
    let removed = 0;
    for (const tx of txs) {
      if (this.remove(txid(tx))) removed++;
    }
    return removed;
  }

  /**
   * Re-admit the transactions of a disconnected block.
   *
   * Skipping the coinbase, which cannot exist outside its block. Anything that
   * no longer validates against the new tip is simply not re-admitted.
   */
  onBlockDisconnected(
    txs: readonly Transaction[],
    state: WorldState,
    height: number,
    time: number,
  ): number {
    let restored = 0;
    for (const tx of txs) {
      if (tx.kind === 'coinbase') continue;
      const res = this.add(tx, state, height, time);
      if (res.ok && !res.duplicate) restored++;
    }
    return restored;
  }

  /**
   * Drop anything that no longer applies to the current tip, and anything
   * that has sat unmined for too long.
   *
   * Called after every tip change. Without it, a pool slowly fills with
   * transactions whose inputs a reorg consumed.
   */
  revalidate(state: WorldState, height: number, time: number): number {
    const dropped: Hex[] = [];
    for (const entry of this.#entries.values()) {
      if (height - entry.addedAtHeight > this.expiryBlocks) {
        dropped.push(entry.txid);
        continue;
      }
      const draft = state.clone();
      const res = applyTx(entry.tx, draft, { height: height + 1, time });
      if (!res.ok) dropped.push(entry.txid);
    }
    for (const id of dropped) this.remove(id);
    return dropped.length;
  }

  /* ────────────────────────────────────────────────── block template ── */

  /**
   * Transactions for a block template, most profitable first.
   *
   * Parents are emitted before children even when a child pays more — a block
   * containing a child without its parent is invalid, so dependency order is
   * not negotiable and fee order is only a tiebreaker within it.
   */
  forBlock(limit = 4000): Transaction[] {
    const byFee = [...this.#entries.values()].sort((a, b) => b.feeRate - a.feeRate);

    const pooled = new Set(this.#entries.keys());
    const emitted = new Set<Hex>();
    const out: Transaction[] = [];

    const visit = (entry: MempoolEntry, depth: number): void => {
      if (emitted.has(entry.txid) || out.length >= limit || depth > 25) return;
      // Emit any pooled parents first.
      for (const input of entry.tx.inputs) {
        if (!pooled.has(input.txid) || emitted.has(input.txid)) continue;
        const parent = this.#entries.get(input.txid);
        if (parent) visit(parent, depth + 1);
      }
      if (emitted.has(entry.txid) || out.length >= limit) return;
      emitted.add(entry.txid);
      out.push(entry.tx);
    };

    for (const entry of byFee) visit(entry, 0);
    return out;
  }

  #evictCheapest(): void {
    let victim: MempoolEntry | undefined;
    for (const entry of this.#entries.values()) {
      if (!victim || entry.feeRate < victim.feeRate) victim = entry;
    }
    if (victim) this.remove(victim.txid);
  }

  stats() {
    const entries = this.entries();
    const bytes = entries.reduce((n, e) => n + e.size, 0);
    const fees = entries.reduce((n, e) => n + e.fee, 0n);
    return {
      count: entries.length,
      bytes,
      totalFees: fees.toString(),
      minFeeRate: entries.length ? Math.min(...entries.map((e) => e.feeRate)) : 0,
      maxFeeRate: entries.length ? Math.max(...entries.map((e) => e.feeRate)) : 0,
    };
  }
}
