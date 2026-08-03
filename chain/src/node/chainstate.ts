/**
 * Persistent chain state with reorganisation.
 *
 * The in-memory `Blockchain` in `src/chain.ts` only ever appends. That is fine
 * for a test harness and useless on a network, where two miners find a block
 * at the same height every so often and one branch has to be undone.
 *
 * `ChainState` adds the three things a real node needs:
 *
 *   1. **Durability.** Blocks and the UTXO set live in SQLite. A restarted
 *      node resumes from its tip instead of replaying from genesis.
 *   2. **A block index, not a list.** Every block ever received is retained,
 *      including ones on branches that lost. A branch that loses today can win
 *      tomorrow, and a node that discarded it would have to re-download.
 *   3. **Undo records.** Disconnecting a block restores the exact prior state
 *      in O(inputs), not by replaying the chain.
 *
 * Fork choice is most-accumulated-work. When a stored block's chainwork
 * exceeds the active tip's, the node walks back to the common ancestor,
 * disconnects, and connects forward along the new branch. If any block on the
 * new branch turns out to be invalid, the whole move is rolled back and the
 * original tip is restored — a failed reorg must never leave a node on a
 * half-applied chain.
 */

import {
  blockHash,
  blockSubsidy,
  blockWork,
  checkHeader,
  computeMerkleRoot,
  mine,
  nextBits,
  BLOCK_GAS_LIMIT,
  RETARGET_INTERVAL,
  type Block,
  type BlockHeader,
} from '../block.ts';
import { applyTx, auditSupplyOf, Blockchain, type SupplyAudit } from '../chain.ts';
import type { Hex } from '../crypto.ts';
import { WorldState, outpoint, type ContractAccount, type Utxo } from '../state.ts';
import { coinbaseTx, txid, type Transaction } from '../tx.ts';
import type { VmLog } from '../vm.ts';
import { UNDO_RETENTION, type NetworkParams } from '../params.ts';
import { ChainStore, type BlockUndo, type StoredHeader } from '../store/sqlite.ts';

export const ACCEPT = {
  /** New block, now on the active chain. */
  CONNECTED: 'connected',
  /** Valid, stored, but on a branch with less work than the tip. */
  SIDECHAIN: 'sidechain',
  /** Already had it. */
  DUPLICATE: 'duplicate',
  /** Parent unknown — the caller should fetch it and retry. */
  ORPHAN: 'orphan',
  /** Failed validation. The peer that sent it deserves a ban score. */
  INVALID: 'invalid',
} as const;

export type AcceptStatus = (typeof ACCEPT)[keyof typeof ACCEPT];

export interface AcceptResult {
  readonly status: AcceptStatus;
  readonly hash: Hex;
  readonly height?: number;
  readonly error?: string;
  /** Blocks disconnected, then connected, when a reorg happened. */
  readonly reorg?: { readonly disconnected: Hex[]; readonly connected: Hex[] };
}

export interface ChainStateOptions {
  readonly params: NetworkParams;
  readonly store: ChainStore;
  /** Retained undo depth. Deeper reorgs are refused rather than mis-applied. */
  readonly undoRetention?: number;
}

export class ChainState {
  readonly params: NetworkParams;
  readonly store: ChainStore;
  readonly undoRetention: number;

  /** World state of the active tip. */
  state: WorldState;
  #tip: StoredHeader;
  /** Contract logs by height, for RPC. Bounded to recent blocks. */
  readonly logsByHeight = new Map<number, VmLog[]>();

  private constructor(opts: ChainStateOptions, state: WorldState, tip: StoredHeader) {
    this.params = opts.params;
    this.store = opts.store;
    this.undoRetention = opts.undoRetention ?? UNDO_RETENTION;
    this.state = state;
    this.#tip = tip;
  }

  /**
   * Open a chain, bootstrapping genesis if the store is empty.
   *
   * A store that already holds a genesis for a *different* network is a hard
   * error rather than a silent re-sync: pointing a mainnet node at a testnet
   * datadir should fail immediately, not corrupt both.
   */
  static open(opts: ChainStateOptions): ChainState {
    const { params, store } = opts;

    if (store.isEmpty) {
      const genesis = Blockchain.create({
        bits: params.bits,
        seed: params.genesisSeed,
        memo: params.genesisMemo,
        time: params.genesisTime,
      });
      const block = genesis.tip;
      const hash = blockHash(block.header);
      const work = blockWork(block.header.bits);

      store.transaction(() => {
        store.putBlock(block, work, true);
        store.writeState(genesis.state);
        store.setTip(hash);
        store.setMeta('network', params.name);
        store.setMeta('genesis', hash);
      });

      return new ChainState(opts, genesis.state, store.getHeader(hash)!);
    }

    const storedNetwork = store.getMeta('network');
    if (storedNetwork && storedNetwork !== params.name) {
      throw new Error(
        `datadir holds a '${storedNetwork}' chain but this node is configured for '${params.name}'`,
      );
    }

    const tipHash = store.tipHash;
    if (!tipHash) throw new Error('store has blocks but no tip — database is corrupt');
    const tip = store.getHeader(tipHash);
    if (!tip) throw new Error(`store tip ${tipHash} is not a known block — database is corrupt`);

    return new ChainState(opts, store.readState(), tip);
  }

  /* ─────────────────────────────────────────────────────────── views ── */

  get tip(): StoredHeader {
    return this.#tip;
  }

  get height(): number {
    return this.#tip.height;
  }

  get tipHash(): Hex {
    return this.#tip.hash;
  }

  get chainWork(): bigint {
    return this.#tip.chainWork;
  }

  getBlock(hash: Hex): Block | undefined {
    return this.store.getBlock(hash);
  }

  getHeader(hash: Hex): StoredHeader | undefined {
    return this.store.getHeader(hash);
  }

  hasBlock(hash: Hex): boolean {
    return this.store.hasBlock(hash);
  }

  headerAt(height: number): StoredHeader | undefined {
    return this.store.getActiveAt(height);
  }

  auditSupply(): SupplyAudit {
    return auditSupplyOf(this.state, this.height);
  }

  /**
   * Block locator: exponentially sparser hashes back from the tip.
   *
   * A peer compares this against its own chain to find the highest block both
   * sides share, in O(log n) round trips rather than by sending every hash.
   */
  locator(): Hex[] {
    const hashes: Hex[] = [];
    let step = 1;
    let height = this.height;
    while (height >= 0) {
      const header = this.store.getActiveAt(height);
      if (header) hashes.push(header.hash);
      if (hashes.length >= 10) step *= 2;
      height -= step;
      if (hashes.length > 32) break;
    }
    const genesis = this.store.getActiveAt(0);
    if (genesis && hashes[hashes.length - 1] !== genesis.hash) hashes.push(genesis.hash);
    return hashes;
  }

  /** Highest active block that appears in `locator`, or genesis. */
  findForkPoint(locator: readonly Hex[]): StoredHeader {
    for (const hash of locator) {
      const header = this.store.getHeader(hash);
      if (header?.active) return header;
    }
    return this.store.getActiveAt(0)!;
  }

  /* ────────────────────────────────────────────── contextual validation ── */

  /** Median of the 11 blocks preceding and including `hash`. */
  medianTimePastAt(hash: Hex): number {
    const times: number[] = [];
    let cursor: StoredHeader | undefined = this.store.getHeader(hash);
    while (cursor && times.length < 11) {
      times.push(cursor.time);
      if (cursor.height === 0) break;
      cursor = this.store.getHeader(cursor.prevHash);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)];
  }

  /** Difficulty a child of `parent` must carry. */
  nextBitsAfter(parent: StoredHeader): number {
    const childHeight = parent.height + 1;
    if (childHeight % RETARGET_INTERVAL !== 0) return parent.bits;

    // Walk back one full retarget window along this branch.
    let cursor: StoredHeader | undefined = parent;
    for (let i = 0; i < RETARGET_INTERVAL - 1 && cursor && cursor.height > 0; i++) {
      cursor = this.store.getHeader(cursor.prevHash);
    }
    if (!cursor) return parent.bits;
    return nextBits(parent.bits, parent.time - cursor.time);
  }

  /* ────────────────────────────────────────────────────── block intake ── */

  /**
   * Validate, store, and possibly activate a block.
   *
   * Contextual checks are made against the block's *parent*, not the current
   * tip — a block arriving on a side branch is still a valid block, and must
   * be retained in case that branch later wins.
   */
  acceptBlock(block: Block, now: number = Math.floor(Date.now() / 1000)): AcceptResult {
    const hash = blockHash(block.header);

    if (this.store.hasBlock(hash)) return { status: ACCEPT.DUPLICATE, hash };

    const headerCheck = checkHeader(block, now);
    if (!headerCheck.ok) return { status: ACCEPT.INVALID, hash, error: headerCheck.error };

    const parent = this.store.getHeader(block.header.prevHash);
    if (!parent) return { status: ACCEPT.ORPHAN, hash, error: `unknown parent ${block.header.prevHash}` };

    if (block.header.height !== parent.height + 1) {
      return {
        status: ACCEPT.INVALID,
        hash,
        error: `height ${block.header.height} does not follow parent ${parent.height}`,
      };
    }

    const expectedBits = this.nextBitsAfter(parent);
    if (block.header.bits !== expectedBits) {
      return {
        status: ACCEPT.INVALID,
        hash,
        error: `wrong difficulty: expected 0x${expectedBits.toString(16)}, got 0x${block.header.bits.toString(16)}`,
      };
    }

    const mtp = this.medianTimePastAt(parent.hash);
    if (block.header.time <= mtp) {
      return { status: ACCEPT.INVALID, hash, error: `time ${block.header.time} is not past MTP ${mtp}` };
    }

    const work = parent.chainWork + blockWork(block.header.bits);

    // Extending the tip directly is the common case: validate and connect.
    if (parent.hash === this.tipHash) {
      const connected = this.#connect(block, work);
      if (!connected.ok) return { status: ACCEPT.INVALID, hash, error: connected.error };
      return { status: ACCEPT.CONNECTED, hash, height: block.header.height };
    }

    // Otherwise store it on its branch. Full validation happens if and when
    // that branch is activated — a side-branch block cannot be validated
    // without first rewinding state to its parent.
    this.store.transaction(() => this.store.putBlock(block, work, false));

    if (work > this.#tip.chainWork) {
      const target = this.store.getHeader(hash)!;
      const reorg = this.#reorgTo(target);
      if (!reorg.ok) return { status: ACCEPT.INVALID, hash, error: reorg.error };
      return {
        status: ACCEPT.CONNECTED,
        hash,
        height: block.header.height,
        reorg: { disconnected: reorg.disconnected, connected: reorg.connected },
      };
    }

    return { status: ACCEPT.SIDECHAIN, hash, height: block.header.height };
  }

  /* ──────────────────────────────────────────────────── connect / undo ── */

  /**
   * Apply `block` to the active state.
   *
   * The undo record is built from reads *before* anything mutates, and the
   * transactions are applied to a clone. Only once the state root matches the
   * header's commitment is the clone promoted and the store written. A block
   * that fails validation leaves no trace.
   */
  #connect(block: Block, work: bigint): { ok: boolean; error?: string } {
    const { header } = block;
    const draft = this.state.clone();

    // ---- undo record, gathered from the pre-application state -------------
    const spent: Utxo[] = [];
    const created: string[] = [];
    const contractsBefore = new Map<string, ContractAccount | null>();
    const noncesBefore: Record<string, number> = {};

    for (const tx of block.transactions) {
      for (const input of tx.inputs) {
        const u = this.state.getUtxo(input.txid, input.vout);
        if (u) spent.push(u);
      }
      const id = txid(tx);
      tx.outputs.forEach((_, vout) => created.push(outpoint(id, vout)));

      if (tx.contract) {
        const target = tx.contract.target;
        if (target && !contractsBefore.has(target)) {
          contractsBefore.set(target, this.state.getContract(target) ?? null);
        }
      }
    }
    // Deploys create a contract whose address is only known after execution,
    // so record every address the block ends up touching after the fact.

    // ---- apply -------------------------------------------------------------
    let totalFees = 0n;
    let totalGas = 0;
    const logs: VmLog[] = [];

    for (const tx of block.transactions.slice(1)) {
      const res = applyTx(tx, draft, { height: header.height, time: header.time });
      if (!res.ok) return { ok: false, error: `tx ${txid(tx)}: ${res.error}` };
      totalFees += res.fee;
      totalGas += res.gasUsed;
      logs.push(...res.logs);
      if (totalGas > BLOCK_GAS_LIMIT) {
        return { ok: false, error: `block gas ${totalGas} exceeds limit ${BLOCK_GAS_LIMIT}` };
      }
      if (res.contractAddress && !contractsBefore.has(res.contractAddress)) {
        contractsBefore.set(res.contractAddress, null);
      }
      if (tx.contract) {
        const deployer = res.contractAddress
          ? draft.getContract(res.contractAddress)?.deployer
          : undefined;
        if (deployer !== undefined && noncesBefore[deployer] === undefined) {
          noncesBefore[deployer] = this.state.nonceOf(deployer);
        }
      }
    }

    const cb = applyTx(block.transactions[0], draft, {
      height: header.height,
      time: header.time,
      availableFees: totalFees,
    });
    if (!cb.ok) return { ok: false, error: `coinbase: ${cb.error}` };

    const computed = draft.stateRoot();
    if (computed !== header.stateRoot) {
      return { ok: false, error: `state root mismatch: header ${header.stateRoot} vs computed ${computed}` };
    }

    // ---- commit ------------------------------------------------------------
    const hash = blockHash(header);
    const undo: BlockUndo = {
      height: header.height,
      hash,
      spent,
      created,
      contracts: [...contractsBefore].map(([address, before]) => ({ address, before })),
      nonces: noncesBefore,
    };

    this.store.transaction(() => {
      this.store.putBlock(block, work, true);
      this.store.putUndo(undo);

      for (const u of spent) this.store.removeUtxo(u.txid, u.vout);
      for (const key of created) {
        const [id, voutStr] = key.split(':');
        const u = draft.getUtxo(id, Number(voutStr));
        if (u) this.store.addUtxo(u);
      }
      for (const [address] of contractsBefore) {
        const now = draft.getContract(address);
        if (now) this.store.putContract(now);
        else this.store.removeContract(address);
      }
      for (const address of Object.keys(noncesBefore)) {
        this.store.setNonce(address, draft.nonceOf(address));
      }

      this.store.setTip(hash);
      if (header.height > this.undoRetention) {
        this.store.pruneUndo(header.height - this.undoRetention);
      }
    });

    this.state = draft;
    this.#tip = this.store.getHeader(hash)!;
    if (logs.length > 0) this.logsByHeight.set(header.height, logs);

    return { ok: true };
  }

  /** Roll the active tip back by one block using its undo record. */
  #disconnect(): { ok: boolean; error?: string } {
    const hash = this.tipHash;
    const header = this.#tip;
    if (header.height === 0) return { ok: false, error: 'cannot disconnect genesis' };

    const undo = this.store.getUndo(hash);
    if (!undo) {
      return {
        ok: false,
        error: `no undo record for ${hash} — reorg deeper than the ${this.undoRetention}-block retention window`,
      };
    }

    const restored = this.state.clone();
    for (const key of undo.created) {
      const [id, voutStr] = key.split(':');
      if (restored.hasUtxo(id, Number(voutStr))) restored.spendUtxo(id, Number(voutStr));
    }
    for (const u of undo.spent) {
      if (!restored.hasUtxo(u.txid, u.vout)) restored.addUtxo(u);
    }
    for (const { address, before } of undo.contracts) {
      if (before) restored.putContract(before);
      else restored.dropContract(address);
    }
    for (const [address, nonce] of Object.entries(undo.nonces)) {
      restored.setNonce(address, nonce);
    }

    const parent = this.store.getHeader(header.prevHash);
    if (!parent) return { ok: false, error: `parent ${header.prevHash} missing during disconnect` };

    // The restored state must reproduce the parent's committed root. If it
    // does not, the undo record is wrong and continuing would silently fork
    // this node off the network.
    const parentBlock = this.store.getBlock(parent.hash);
    const expectedRoot = parentBlock?.header.stateRoot;
    const actualRoot = restored.stateRoot();
    if (expectedRoot && actualRoot !== expectedRoot) {
      return {
        ok: false,
        error: `undo produced state root ${actualRoot}, parent commits ${expectedRoot}`,
      };
    }

    this.store.transaction(() => {
      this.store.setActive(hash, false);
      this.store.writeState(restored);
      this.store.setTip(parent.hash);
    });

    this.state = restored;
    this.#tip = parent;
    this.logsByHeight.delete(header.height);
    return { ok: true };
  }

  /**
   * Move the active chain to `target`.
   *
   * Walks back to the common ancestor, disconnects, then connects forward. On
   * any failure the original tip is restored, so a bad branch cannot leave the
   * node stranded on a partially applied chain.
   */
  #reorgTo(target: StoredHeader): {
    ok: boolean;
    error?: string;
    disconnected: Hex[];
    connected: Hex[];
  } {
    const originalTip = this.#tip;

    // Path from `target` back to the first block already on the active chain.
    const branch: StoredHeader[] = [];
    let cursor: StoredHeader | undefined = target;
    while (cursor && !cursor.active) {
      branch.push(cursor);
      cursor = this.store.getHeader(cursor.prevHash);
    }
    if (!cursor) {
      return { ok: false, error: 'branch does not connect to the active chain', disconnected: [], connected: [] };
    }
    const forkPoint = cursor;
    branch.reverse();

    if (this.height - forkPoint.height > this.undoRetention) {
      return {
        ok: false,
        error: `reorg of depth ${this.height - forkPoint.height} exceeds the ${this.undoRetention}-block undo window`,
        disconnected: [],
        connected: [],
      };
    }

    const disconnected: Hex[] = [];
    while (this.tipHash !== forkPoint.hash) {
      const hash = this.tipHash;
      const res = this.#disconnect();
      if (!res.ok) {
        this.#restoreTo(originalTip, disconnected, []);
        return { ok: false, error: res.error, disconnected: [], connected: [] };
      }
      disconnected.push(hash);
    }

    const connected: Hex[] = [];
    for (const header of branch) {
      const block = this.store.getBlock(header.hash);
      if (!block) {
        this.#restoreTo(originalTip, disconnected, connected);
        return { ok: false, error: `missing block body for ${header.hash}`, disconnected: [], connected: [] };
      }
      const res = this.#connect(block, header.chainWork);
      if (!res.ok) {
        // The offending block is invalid in this context; drop it so the node
        // does not retry the same doomed reorg on every subsequent block.
        this.store.transaction(() => this.store.setActive(header.hash, false));
        this.#restoreTo(originalTip, disconnected, connected);
        return { ok: false, error: `connecting ${header.hash}: ${res.error}`, disconnected: [], connected: [] };
      }
      connected.push(header.hash);
    }

    return { ok: true, disconnected, connected };
  }

  /** Best-effort return to `original` after a failed reorg. */
  #restoreTo(original: StoredHeader, disconnected: Hex[], connected: Hex[]): void {
    for (let i = connected.length - 1; i >= 0; i--) {
      if (this.tipHash === connected[i]) this.#disconnect();
    }
    for (let i = disconnected.length - 1; i >= 0; i--) {
      const block = this.store.getBlock(disconnected[i]);
      const header = this.store.getHeader(disconnected[i]);
      if (block && header) this.#connect(block, header.chainWork);
    }
    if (this.tipHash !== original.hash) {
      // Nothing further can be done automatically; surface it loudly rather
      // than continue on an unknown chain.
      throw new Error(
        `failed to restore tip after a failed reorg: at ${this.tipHash}, expected ${original.hash}`,
      );
    }
  }

  /* ────────────────────────────────────────────────────── block assembly ── */

  /**
   * Assemble and mine a block on top of the tip.
   *
   * Transactions that fail to apply are reported, not silently dropped.
   */
  mineBlock(
    txs: readonly Transaction[],
    minerAddress: string,
    opts: { time?: number; memo?: string; maxAttempts?: number } = {},
  ): {
    block: Block;
    accepted: AcceptResult;
    rejected: Array<{ txid: Hex; error: string }>;
    attempts: number;
  } {
    const height = this.height + 1;
    const time = opts.time ?? Math.max(Math.floor(Date.now() / 1000), this.medianTimePastAt(this.tipHash) + 1);

    const draft = this.state.clone();
    const included: Transaction[] = [];
    const rejected: Array<{ txid: Hex; error: string }> = [];
    let fees = 0n;
    let gas = 0;

    for (const tx of txs) {
      const res = applyTx(tx, draft, { height, time });
      if (res.ok && gas + res.gasUsed <= BLOCK_GAS_LIMIT) {
        included.push(tx);
        fees += res.fee;
        gas += res.gasUsed;
      } else {
        rejected.push({ txid: txid(tx), error: res.error ?? 'block gas limit reached' });
      }
    }

    const cb = coinbaseTx(minerAddress, blockSubsidy(height) + fees, height, opts.memo ?? `deckx/${height}`);
    applyTx(cb, draft, { height, time, availableFees: fees });

    const template: BlockHeader = {
      version: 1,
      prevHash: this.tipHash,
      merkleRoot: computeMerkleRoot([cb, ...included]),
      stateRoot: draft.stateRoot(),
      time,
      bits: this.nextBitsAfter(this.#tip),
      height,
      nonce: 0,
      extraNonce: 0,
    };

    const mined = mine(template, opts.maxAttempts);
    const block: Block = { header: mined.header, transactions: [cb, ...included] };
    const accepted = this.acceptBlock(block, time + 1);
    return { block, accepted, rejected, attempts: mined.attempts };
  }

  /* ───────────────────────────────────────────────────────────── report ── */

  info() {
    const audit = this.auditSupply();
    return {
      network: this.params.name,
      height: this.height,
      tip: this.tipHash,
      chainWork: this.chainWork.toString(),
      utxos: this.state.utxoCount,
      contracts: this.state.contracts().length,
      supply: audit.utxoTotal.toString(),
      supplyBalanced: audit.balanced,
      store: this.store.stats(),
    };
  }
}
