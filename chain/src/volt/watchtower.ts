/**
 * Volt watchtower.
 *
 * The penalty transaction closes the theft loophole in payment channels — but
 * only if somebody broadcasts it. Without a tower a channel is safe only while
 * its owner is online, and "mostly online" is not a security property.
 *
 * ── The privacy problem, and how this handles it ──────────────────────────
 * A naive tower is told "here are my channels, here are my revocation secrets"
 * and thereby learns the user's entire payment graph. That is a worse leak
 * than the risk it removes.
 *
 * Instead, each update registers a **blob keyed by a hint**:
 *
 *   hint = first 16 bytes of the commitment txid
 *   key  = last 16 bytes of the same txid
 *   blob = encrypt(key, penalty transaction)
 *
 * The tower stores `(hint, blob)` and learns nothing: it cannot derive the key
 * from the hint, so it cannot read the blob or even tell which channel it
 * belongs to. When a commitment appears on-chain the tower sees the full txid,
 * looks up the hint, derives the key from the half it now knows, decrypts, and
 * broadcasts. This is the construction Lightning's BOLT-13 draft describes, and
 * it is worth the extra code because it makes running a tower for strangers
 * safe.
 *
 * ── Fee ladders ───────────────────────────────────────────────────────────
 * A penalty's fee is fixed when the blob is sealed, because the transaction is
 * signed at that moment. If fees spike between then and the breach, the
 * penalty may never confirm — and an unconfirmable penalty is no penalty. Two
 * approaches exist: child-pays-for-parent, which needs a second transaction
 * and a UTXO the tower controls, or a **fee ladder**, where the client seals
 * the same penalty at several fee levels and the tower escalates.
 *
 * The ladder is implemented here. It costs the client a few extra signatures
 * once and requires nothing of the tower but a retry loop. The tower starts at
 * the cheapest rung that clears the current floor and climbs each time a
 * broadcast fails or a penalty goes unconfirmed for `retryAfterBlocks`.
 *
 * ── Persistence ───────────────────────────────────────────────────────────
 * Blobs go to SQLite. A tower that forgets its blobs on restart protects a
 * channel until the first reboot, which is worse than useless because the user
 * believes they are covered. The store is as blind as the tower.
 *
 * ── What is still missing ─────────────────────────────────────────────────
 * No reward mechanism, so nobody is paid to run one. No accountability: a
 * tower that quietly does nothing is indistinguishable from one that is
 * working, right up until it matters.
 */

import { concat, fromHex, sha256, taggedHash, toHex, type Hex } from '../crypto.ts';
import { txid, type Transaction } from '../tx.ts';
import type { Block } from '../block.ts';
import { VoltChannel } from './channel.ts';
import type { ChainStore } from '../store/sqlite.ts';

/** Bytes of the commitment txid used as the lookup hint. */
export const HINT_BYTES = 16;

/** Fee levels a client seals by default, in zaps. Roughly 1×, 4×, 16×, 64×. */
export const DEFAULT_FEE_LADDER: readonly bigint[] = [1_000n, 4_000n, 16_000n, 64_000n];

/** Blocks a penalty may go unconfirmed before the tower climbs a rung. */
export const DEFAULT_RETRY_AFTER = 3;

export interface WatchBlob {
  /** Lookup key: the first `HINT_BYTES` of the commitment txid, hex. */
  readonly hint: Hex;
  /** Encrypted penalty transaction. */
  readonly payload: Hex;
  /** Authenticates the payload before it is parsed. */
  readonly mac: Hex;
  /** Commitment number, so a tower can drop superseded blobs. Not identifying. */
  readonly sequence: number;
  /** Fee this rung pays, in zaps. Visible to the tower so it can order rungs. */
  readonly fee: bigint;
}

export interface BreachReport {
  readonly hint: Hex;
  readonly commitmentTxid: Hex;
  readonly height: number;
  readonly penalty: Transaction;
  readonly sweptZaps: bigint;
  readonly fee: bigint;
  /** Which rung of the ladder was used, counting from zero. */
  readonly rung: number;
}

/* ────────────────────────────────────────────────────────── crypto ── */

const encryptionKey = (txidHex: Hex): Uint8Array =>
  taggedHash('Volt/watchtower/key', fromHex(txidHex).subarray(HINT_BYTES));

const macKey = (key: Uint8Array): Uint8Array => taggedHash('Volt/watchtower/mac', key);

/** SHA-256 counter-mode keystream. Same construction as the onion's `rho`. */
function keystream(key: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const block = sha256(concat(key, Uint8Array.of(counter >> 8, counter & 0xff)));
    out.set(block.subarray(0, Math.min(32, length - offset)), offset);
    offset += 32;
    counter++;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Build the blob a client hands to a tower.
 *
 * The client knows the commitment txid because it holds the commitment. The
 * tower receives only the first half of it.
 *
 * The fee is *not* encrypted. A tower must be able to order the rungs of a
 * ladder without reading them, and the fee alone identifies nothing — it is a
 * number the tower could infer anyway by watching which rung confirms.
 */
export function sealBlob(
  commitmentTxid: Hex,
  penalty: Transaction,
  sequence: number,
  fee: bigint,
): WatchBlob {
  const key = encryptionKey(commitmentTxid);
  const plaintext = encoder.encode(JSON.stringify(penalty));
  const payload = xor(plaintext, keystream(key, plaintext.length));
  return {
    hint: commitmentTxid.slice(0, HINT_BYTES * 2),
    payload: toHex(payload),
    mac: toHex(taggedHash('Volt/watchtower/tag', macKey(key), payload)),
    sequence,
    fee,
  };
}

/**
 * Open a blob once the commitment has appeared on-chain.
 *
 * Returns `undefined` on a MAC failure rather than throwing: a tower holding a
 * corrupt blob should skip it, not crash and stop protecting every other
 * channel it watches.
 */
export function openBlob(commitmentTxid: Hex, blob: WatchBlob): Transaction | undefined {
  const key = encryptionKey(commitmentTxid);
  const payload = fromHex(blob.payload);
  const expected = toHex(taggedHash('Volt/watchtower/tag', macKey(key), payload));
  if (expected !== blob.mac) return undefined;

  try {
    return JSON.parse(decoder.decode(xor(payload, keystream(key, payload.length)))) as Transaction;
  } catch {
    return undefined;
  }
}

/* ─────────────────────────────────────────────────────────── tower ── */

export interface WatchtowerOptions {
  /** Publishes a penalty. Returns true when it was accepted for relay. */
  readonly broadcast: (tx: Transaction, fee: bigint) => boolean;
  /** Optional durable store. Without one, blobs are lost on restart. */
  readonly store?: ChainStore;
  /** Blocks a penalty may go unconfirmed before climbing a fee rung. */
  readonly retryAfterBlocks?: number;
  /** Reports whether a transaction has confirmed. Enables the retry loop. */
  readonly isConfirmed?: (id: Hex) => boolean;
}

/** A breach that has been acted on but has not yet confirmed. */
interface PendingPenalty {
  readonly hint: Hex;
  readonly commitmentTxid: Hex;
  penaltyTxid: Hex;
  rung: number;
  broadcastAtHeight: number;
}

export class Watchtower {
  /** In-memory index. Mirrors the store when one is configured. */
  readonly #blobs = new Map<Hex, WatchBlob[]>();
  readonly #pending = new Map<Hex, PendingPenalty>();
  readonly #broadcast: (tx: Transaction, fee: bigint) => boolean;
  readonly #store?: ChainStore;
  readonly #retryAfter: number;
  readonly #isConfirmed?: (id: Hex) => boolean;

  readonly breaches: BreachReport[] = [];
  scannedBlocks = 0;
  escalations = 0;

  constructor(opts: WatchtowerOptions) {
    this.#broadcast = opts.broadcast;
    this.#store = opts.store;
    this.#retryAfter = opts.retryAfterBlocks ?? DEFAULT_RETRY_AFTER;
    this.#isConfirmed = opts.isConfirmed;

    // Rehydrate from disk. A tower that forgets on restart protects a channel
    // until the first reboot, which is worse than not existing — the user
    // believes they are covered.
    if (this.#store) {
      for (const hint of this.#store.watchHints()) {
        const rows = this.#store.watchBlobs(hint);
        this.#blobs.set(
          hint,
          rows.map((r) => ({ ...r, fee: BigInt(r.fee) })),
        );
      }
    }
  }

  get blobCount(): number {
    let n = 0;
    for (const list of this.#blobs.values()) n += list.length;
    return n;
  }

  get hintCount(): number {
    return this.#blobs.size;
  }

  get pendingCount(): number {
    return this.#pending.size;
  }

  /**
   * Accept a blob. The tower cannot tell which channel it belongs to, who the
   * parties are, or how much is at stake — only the fee rung, which it needs
   * in order to escalate.
   */
  register(blob: WatchBlob): void {
    const list = this.#blobs.get(blob.hint) ?? [];
    if (list.some((b) => b.sequence === blob.sequence && b.fee === blob.fee && b.mac === blob.mac)) {
      return;
    }
    list.push(blob);
    // Newest commitment first; cheapest rung first within a commitment.
    list.sort((a, b) => (b.sequence - a.sequence) || Number(a.fee - b.fee));
    this.#blobs.set(blob.hint, list);

    this.#store?.putWatchBlob({
      hint: blob.hint,
      sequence: blob.sequence,
      fee: blob.fee.toString(),
      payload: blob.payload,
      mac: blob.mac,
    });
  }

  /** Register every rung of a ladder at once. */
  registerLadder(blobs: readonly WatchBlob[]): number {
    for (const blob of blobs) this.register(blob);
    return blobs.length;
  }

  /**
   * Scan a block for revoked commitments.
   *
   * Also drives the retry loop: a penalty that was broadcast but has not
   * confirmed within `retryAfterBlocks` is re-broadcast one rung higher.
   */
  scanBlock(block: Block): BreachReport[] {
    this.scannedBlocks++;
    const found: BreachReport[] = [];

    for (const tx of block.transactions) {
      const id = txid(tx);
      const hint = id.slice(0, HINT_BYTES * 2);
      const blobs = this.#blobs.get(hint);
      if (!blobs || this.#pending.has(hint)) continue;

      const report = this.#act(hint, id, blobs, 0, block.header.height);
      if (report) found.push(report);
    }

    this.#retryStalled(block.header.height);
    return found;
  }

  /** Try rung `rung` and upwards until one broadcasts. */
  #act(
    hint: Hex,
    commitmentTxid: Hex,
    blobs: readonly WatchBlob[],
    fromRung: number,
    height: number,
  ): BreachReport | undefined {
    // Only rungs for the newest commitment we hold for this hint are relevant.
    const newest = blobs[0]?.sequence;
    const ladder = blobs.filter((b) => b.sequence === newest);

    for (let rung = fromRung; rung < ladder.length; rung++) {
      const penalty = openBlob(commitmentTxid, ladder[rung]);
      if (!penalty) continue;

      const swept = penalty.outputs.reduce((sum, o) => sum + BigInt(o.value), 0n);
      if (!this.#broadcast(penalty, ladder[rung].fee)) continue;

      const report: BreachReport = {
        hint,
        commitmentTxid,
        height,
        penalty,
        sweptZaps: swept,
        fee: ladder[rung].fee,
        rung,
      };
      this.breaches.push(report);
      this.#pending.set(hint, {
        hint,
        commitmentTxid,
        penaltyTxid: txid(penalty),
        rung,
        broadcastAtHeight: height,
      });
      return report;
    }
    return undefined;
  }

  /**
   * Re-broadcast penalties that have not confirmed, one fee rung higher.
   *
   * Requires an `isConfirmed` callback; without one the tower has no way to
   * know whether its penalty landed, and escalating blindly would double-spend
   * against itself.
   */
  #retryStalled(height: number): void {
    if (!this.#isConfirmed) return;

    for (const [hint, pending] of [...this.#pending]) {
      if (this.#isConfirmed(pending.penaltyTxid)) {
        // Landed. The channel is closed; nothing else for this hint matters.
        this.#pending.delete(hint);
        this.forget(hint);
        continue;
      }
      if (height - pending.broadcastAtHeight < this.#retryAfter) continue;

      const blobs = this.#blobs.get(hint);
      if (!blobs) {
        this.#pending.delete(hint);
        continue;
      }

      this.#pending.delete(hint);
      const escalated = this.#act(hint, pending.commitmentTxid, blobs, pending.rung + 1, height);
      if (escalated) this.escalations++;
      else {
        // Top of the ladder reached and still unconfirmed. Nothing further can
        // be done automatically; leave the blobs so a later scan can retry.
        this.#pending.set(hint, { ...pending, broadcastAtHeight: height });
      }
    }
  }

  scanBlocks(blocks: Iterable<Block>): BreachReport[] {
    const all: BreachReport[] = [];
    for (const block of blocks) all.push(...this.scanBlock(block));
    return all;
  }

  /** Forget a channel's blobs, e.g. after a cooperative close. */
  forget(hint: Hex): boolean {
    this.#store?.forgetWatchBlobs(hint);
    this.#pending.delete(hint);
    return this.#blobs.delete(hint);
  }

  stats() {
    return {
      hints: this.hintCount,
      blobs: this.blobCount,
      pending: this.pendingCount,
      scannedBlocks: this.scannedBlocks,
      breachesCaught: this.breaches.length,
      escalations: this.escalations,
      persistent: this.#store !== undefined,
      sweptZaps: this.breaches.reduce((s, b) => s + b.sweptZaps, 0n).toString(),
    };
  }
}

/* ──────────────────────────────────────────────────────── client ── */

/**
 * Seal a fee ladder for one revoked state.
 *
 * Called by a channel party immediately *before* advancing to the next
 * commitment — at that moment it holds both the old commitment and the
 * revocation material needed to punish it.
 *
 * Rungs whose fee exceeds the swept value are skipped rather than sealed: a
 * penalty that pays more in fees than it recovers is not a penalty.
 */
export function ladderForRevokedState(
  channel: VoltChannel,
  revokedNumber: number,
  cheater: 'a' | 'b',
  sweepTo: string,
  feeLadder: readonly bigint[] = DEFAULT_FEE_LADDER,
): WatchBlob[] {
  const bundle = channel.history[revokedNumber];
  if (!bundle) return [];

  const commitment = cheater === 'a' ? bundle.forA : bundle.forB;
  const commitmentId = txid(commitment);
  const blobs: WatchBlob[] = [];

  for (const fee of feeLadder) {
    try {
      const penalty = channel.penaltyFor(commitment, revokedNumber, cheater, sweepTo, fee);
      blobs.push(sealBlob(commitmentId, penalty, revokedNumber, fee));
    } catch {
      // Either every output is dust, or this rung's fee exceeds what there is
      // to sweep. Higher rungs will fail the same way, so stop climbing.
      break;
    }
  }
  return blobs;
}

/** Single-rung convenience wrapper. */
export function blobForRevokedState(
  channel: VoltChannel,
  revokedNumber: number,
  cheater: 'a' | 'b',
  sweepTo: string,
  feeZaps = DEFAULT_FEE_LADDER[0],
): WatchBlob | undefined {
  return ladderForRevokedState(channel, revokedNumber, cheater, sweepTo, [feeZaps])[0];
}

/**
 * Register ladders for every state a channel has already revoked.
 *
 * The bulk-import path a wallet uses when it first hires a tower. Returns the
 * number of *commitments* covered, not the number of blobs.
 */
export function backfill(
  tower: Watchtower,
  channel: VoltChannel,
  cheater: 'a' | 'b',
  sweepTo: string,
  feeLadder: readonly bigint[] = DEFAULT_FEE_LADDER,
): number {
  let covered = 0;
  for (let n = 0; n < channel.commitmentNumber; n++) {
    const ladder = ladderForRevokedState(channel, n, cheater, sweepTo, feeLadder);
    if (ladder.length > 0) {
      tower.registerLadder(ladder);
      covered++;
    }
  }
  return covered;
}
