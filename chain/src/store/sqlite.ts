/**
 * Durable storage.
 *
 * Backed by `node:sqlite`, which ships with Node — no new dependency, no
 * native build step, and a real B-tree with real transactions instead of a
 * JSON file that corrupts on power loss.
 *
 * ── What is stored, and why each table exists ─────────────────────────────
 *
 *   blocks      every block ever accepted, including ones on abandoned
 *               branches. A reorg needs the losing branch to still be
 *               readable, because it may win again later.
 *   utxos       the unspent-output set of the *active* chain only.
 *   contracts   contract code and storage for the active chain.
 *   nonces      deployer nonces for the active chain.
 *   undo        per-block records that let `disconnect` restore the exact
 *               prior state. Without these a reorg means replaying from
 *               genesis, which is not viable on a chain of any size.
 *   peers       addresses learned from the network, so a restarted node can
 *               rejoin without a seed.
 *   meta        the active tip and schema version.
 *
 * Everything that mutates state goes through `transaction()`. A block is
 * applied entirely or not at all — a half-written block is the one failure
 * mode that would silently fork a node off the network.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { blockHash, type Block } from '../block.ts';
import { txid, type Transaction } from '../tx.ts';
import { WorldState, outpoint, type ContractAccount, type Utxo } from '../state.ts';
import type { Hex } from '../crypto.ts';

export const SCHEMA_VERSION = 1;

/** Everything needed to undo one block's effect on the world state. */
export interface BlockUndo {
  readonly height: number;
  readonly hash: Hex;
  /** Outputs this block spent. Restored on disconnect. */
  readonly spent: readonly Utxo[];
  /** Outpoints this block created. Deleted on disconnect. */
  readonly created: readonly string[];
  /** Contracts as they were before the block. `null` storage means "did not exist". */
  readonly contracts: ReadonlyArray<{ address: string; before: ContractAccount | null }>;
  /** Nonces as they were before the block. */
  readonly nonces: Readonly<Record<string, number>>;
}

export interface StoredHeader {
  readonly hash: Hex;
  readonly prevHash: Hex;
  readonly height: number;
  readonly time: number;
  readonly bits: number;
  /** Accumulated work from genesis through this block. */
  readonly chainWork: bigint;
  /** True when this block is on the currently active chain. */
  readonly active: boolean;
}

export interface PeerRecord {
  readonly host: string;
  readonly port: number;
  readonly lastSeen: number;
  readonly lastSuccess: number;
  readonly failures: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
  hash       TEXT PRIMARY KEY,
  prev_hash  TEXT NOT NULL,
  height     INTEGER NOT NULL,
  time       INTEGER NOT NULL,
  bits       INTEGER NOT NULL,
  chain_work TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 0,
  payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS blocks_height  ON blocks(height);
CREATE INDEX IF NOT EXISTS blocks_prev    ON blocks(prev_hash);
CREATE INDEX IF NOT EXISTS blocks_active  ON blocks(active, height);

CREATE TABLE IF NOT EXISTS utxos (
  outpoint TEXT PRIMARY KEY,
  txid     TEXT NOT NULL,
  vout     INTEGER NOT NULL,
  value    TEXT NOT NULL,
  address  TEXT NOT NULL,
  script   TEXT,
  height   INTEGER NOT NULL,
  coinbase INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS utxos_address ON utxos(address);

CREATE TABLE IF NOT EXISTS contracts (
  address     TEXT PRIMARY KEY,
  code        TEXT NOT NULL,
  storage     TEXT NOT NULL,
  deployed_at INTEGER NOT NULL,
  deployer    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
  address TEXT PRIMARY KEY,
  nonce   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS undo (
  hash    TEXT PRIMARY KEY,
  height  INTEGER NOT NULL,
  payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
  host         TEXT NOT NULL,
  port         INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  last_success INTEGER NOT NULL DEFAULT 0,
  failures     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (host, port)
);
`;

/** JSON with bigint support — values are stored as decimal strings throughout. */
const json = {
  stringify: (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x)),
  parse: <T>(s: string): T => JSON.parse(s) as T,
};

export class ChainStore {
  readonly #db: DatabaseSync;
  readonly path: string;

  constructor(path: string) {
    this.path = path;
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.#db = new DatabaseSync(path);
    // WAL keeps readers from blocking the writer — a node serving RPC while
    // connecting a block should not stall.
    this.#db.exec('PRAGMA journal_mode = WAL');
    this.#db.exec('PRAGMA synchronous = NORMAL');
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#db.exec(SCHEMA);

    const version = this.getMeta('schema_version');
    if (version === undefined) this.setMeta('schema_version', String(SCHEMA_VERSION));
    else if (Number(version) !== SCHEMA_VERSION) {
      throw new Error(
        `ChainStore: database schema is v${version}, this build expects v${SCHEMA_VERSION}`,
      );
    }
  }

  close(): void {
    this.#db.close();
  }

  /**
   * Run `fn` inside a transaction. Rolls back on any throw.
   *
   * Every state mutation in the node goes through here. A block is applied
   * entirely or not at all.
   */
  transaction<T>(fn: () => T): T {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.#db.exec('COMMIT');
      return result;
    } catch (err) {
      this.#db.exec('ROLLBACK');
      throw err;
    }
  }

  /* ─────────────────────────────────────────────────────────── meta ── */

  getMeta(key: string): string | undefined {
    const row = this.#db.prepare('SELECT value FROM meta WHERE key = ?').get(key) as
      | { value: string }
      | undefined;
    return row?.value;
  }

  setMeta(key: string, value: string): void {
    this.#db
      .prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?')
      .run(key, value, value);
  }

  get tipHash(): Hex | undefined {
    return this.getMeta('tip');
  }

  setTip(hash: Hex): void {
    this.setMeta('tip', hash);
  }

  get isEmpty(): boolean {
    const row = this.#db.prepare('SELECT COUNT(*) AS n FROM blocks').get() as { n: number };
    return row.n === 0;
  }

  /* ───────────────────────────────────────────────────────── blocks ── */

  putBlock(block: Block, chainWork: bigint, active: boolean): void {
    const hash = blockHash(block.header);
    this.#db
      .prepare(
        `INSERT INTO blocks (hash, prev_hash, height, time, bits, chain_work, active, payload)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(hash) DO UPDATE SET active = excluded.active, chain_work = excluded.chain_work`,
      )
      .run(
        hash,
        block.header.prevHash,
        block.header.height,
        block.header.time,
        block.header.bits >>> 0,
        chainWork.toString(),
        active ? 1 : 0,
        json.stringify(block),
      );
  }

  getBlock(hash: Hex): Block | undefined {
    const row = this.#db.prepare('SELECT payload FROM blocks WHERE hash = ?').get(hash) as
      | { payload: string }
      | undefined;
    return row ? json.parse<Block>(row.payload) : undefined;
  }

  hasBlock(hash: Hex): boolean {
    return this.#db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(hash) !== undefined;
  }

  getHeader(hash: Hex): StoredHeader | undefined {
    const row = this.#db
      .prepare('SELECT hash, prev_hash, height, time, bits, chain_work, active FROM blocks WHERE hash = ?')
      .get(hash) as Record<string, unknown> | undefined;
    return row ? rowToHeader(row) : undefined;
  }

  /** Block on the active chain at `height`. */
  getActiveAt(height: number): StoredHeader | undefined {
    const row = this.#db
      .prepare(
        'SELECT hash, prev_hash, height, time, bits, chain_work, active FROM blocks WHERE active = 1 AND height = ?',
      )
      .get(height) as Record<string, unknown> | undefined;
    return row ? rowToHeader(row) : undefined;
  }

  /** Active-chain headers from `from` upward, oldest first. */
  activeHeaders(from: number, limit: number): StoredHeader[] {
    const rows = this.#db
      .prepare(
        `SELECT hash, prev_hash, height, time, bits, chain_work, active FROM blocks
         WHERE active = 1 AND height >= ? ORDER BY height ASC LIMIT ?`,
      )
      .all(from, limit) as Array<Record<string, unknown>>;
    return rows.map(rowToHeader);
  }

  /** The stored block with the most accumulated work, active or not. */
  bestHeader(): StoredHeader | undefined {
    // chain_work is a decimal string, so ordering must be by length first —
    // lexicographic comparison of unequal-length numbers is wrong.
    const row = this.#db
      .prepare(
        `SELECT hash, prev_hash, height, time, bits, chain_work, active FROM blocks
         ORDER BY LENGTH(chain_work) DESC, chain_work DESC LIMIT 1`,
      )
      .get() as Record<string, unknown> | undefined;
    return row ? rowToHeader(row) : undefined;
  }

  /** Blocks whose parent is `hash`. Used to walk forward onto a branch. */
  childrenOf(hash: Hex): StoredHeader[] {
    const rows = this.#db
      .prepare(
        'SELECT hash, prev_hash, height, time, bits, chain_work, active FROM blocks WHERE prev_hash = ?',
      )
      .all(hash) as Array<Record<string, unknown>>;
    return rows.map(rowToHeader);
  }

  setActive(hash: Hex, active: boolean): void {
    this.#db.prepare('UPDATE blocks SET active = ? WHERE hash = ?').run(active ? 1 : 0, hash);
  }

  get blockCount(): number {
    return (this.#db.prepare('SELECT COUNT(*) AS n FROM blocks').get() as { n: number }).n;
  }

  get activeHeight(): number {
    const row = this.#db.prepare('SELECT MAX(height) AS h FROM blocks WHERE active = 1').get() as {
      h: number | null;
    };
    return row.h ?? -1;
  }

  /** Locate a transaction by id across the active chain. */
  findTransaction(id: Hex): { tx: Transaction; height: number; blockHash: Hex } | undefined {
    // Blocks are stored as JSON; a LIKE scan is adequate at reference scale and
    // avoids a second index that would need to be kept consistent on reorg.
    const rows = this.#db
      .prepare('SELECT hash, height, payload FROM blocks WHERE active = 1 AND payload LIKE ? ORDER BY height DESC')
      .all(`%${id}%`) as Array<{ hash: string; height: number; payload: string }>;
    for (const row of rows) {
      const block = json.parse<Block>(row.payload);
      const tx = block.transactions.find((t) => txid(t) === id);
      if (tx) return { tx, height: row.height, blockHash: row.hash };
    }
    return undefined;
  }

  /* ─────────────────────────────────────────────────────────── undo ── */

  putUndo(undo: BlockUndo): void {
    this.#db
      .prepare('INSERT OR REPLACE INTO undo (hash, height, payload) VALUES (?, ?, ?)')
      .run(undo.hash, undo.height, json.stringify(undo));
  }

  getUndo(hash: Hex): BlockUndo | undefined {
    const row = this.#db.prepare('SELECT payload FROM undo WHERE hash = ?').get(hash) as
      | { payload: string }
      | undefined;
    if (!row) return undefined;
    const raw = json.parse<BlockUndo>(row.payload);
    // Values round-trip through JSON as strings; restore the bigints.
    return {
      ...raw,
      spent: raw.spent.map((u) => ({ ...u, value: BigInt(u.value as unknown as string) })),
    };
  }

  /** Discard undo records older than `keepFrom`. Bounds disk use on a long chain. */
  pruneUndo(keepFrom: number): number {
    const info = this.#db.prepare('DELETE FROM undo WHERE height < ?').run(keepFrom);
    return Number(info.changes);
  }

  /* ────────────────────────────────────────────────────────── state ── */

  addUtxo(u: Utxo): void {
    this.#db
      .prepare(
        `INSERT OR REPLACE INTO utxos (outpoint, txid, vout, value, address, script, height, coinbase)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        outpoint(u.txid, u.vout),
        u.txid,
        u.vout,
        u.value.toString(),
        u.address,
        u.script ? json.stringify(u.script) : null,
        u.height,
        u.coinbase ? 1 : 0,
      );
  }

  removeUtxo(txidHex: Hex, vout: number): void {
    this.#db.prepare('DELETE FROM utxos WHERE outpoint = ?').run(outpoint(txidHex, vout));
  }

  putContract(c: ContractAccount): void {
    this.#db
      .prepare(
        `INSERT OR REPLACE INTO contracts (address, code, storage, deployed_at, deployer)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(c.address, c.code, json.stringify(c.storage), c.deployedAt, c.deployer);
  }

  removeContract(address: string): void {
    this.#db.prepare('DELETE FROM contracts WHERE address = ?').run(address);
  }

  setNonce(address: string, nonce: number): void {
    this.#db
      .prepare('INSERT OR REPLACE INTO nonces (address, nonce) VALUES (?, ?)')
      .run(address, nonce);
  }

  removeNonce(address: string): void {
    this.#db.prepare('DELETE FROM nonces WHERE address = ?').run(address);
  }

  /** Replace the persisted state wholesale with `state`. */
  writeState(state: WorldState): void {
    this.#db.exec('DELETE FROM utxos');
    this.#db.exec('DELETE FROM contracts');
    this.#db.exec('DELETE FROM nonces');
    for (const u of state.utxos()) this.addUtxo(u);
    for (const c of state.contracts()) this.putContract(c);
    for (const [address, nonce] of Object.entries(state.snapshot().nonces)) {
      this.setNonce(address, nonce);
    }
  }

  /** Load the persisted state back into memory. */
  readState(): WorldState {
    const state = new WorldState();

    const utxoRows = this.#db
      .prepare('SELECT txid, vout, value, address, script, height, coinbase FROM utxos')
      .all() as Array<Record<string, unknown>>;
    for (const r of utxoRows) {
      state.addUtxo({
        txid: r.txid as string,
        vout: Number(r.vout),
        value: BigInt(r.value as string),
        address: r.address as string,
        script: r.script ? json.parse(r.script as string) : undefined,
        height: Number(r.height),
        coinbase: Number(r.coinbase) === 1,
      });
    }

    const contractRows = this.#db
      .prepare('SELECT address, code, storage, deployed_at, deployer FROM contracts')
      .all() as Array<Record<string, unknown>>;
    for (const r of contractRows) {
      state.putContract({
        address: r.address as string,
        code: r.code as string,
        storage: json.parse(r.storage as string),
        deployedAt: Number(r.deployed_at),
        deployer: r.deployer as string,
      });
    }

    const nonceRows = this.#db.prepare('SELECT address, nonce FROM nonces').all() as Array<{
      address: string;
      nonce: number;
    }>;
    for (const r of nonceRows) {
      for (let i = 0; i < r.nonce; i++) state.bumpNonce(r.address);
    }

    return state;
  }

  /* ─────────────────────────────────────────────────────────── peers ── */

  rememberPeer(host: string, port: number, success: boolean): void {
    const now = Math.floor(Date.now() / 1000);
    this.#db
      .prepare(
        `INSERT INTO peers (host, port, last_seen, last_success, failures)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(host, port) DO UPDATE SET
           last_seen    = excluded.last_seen,
           last_success = CASE WHEN ? THEN excluded.last_seen ELSE peers.last_success END,
           failures     = CASE WHEN ? THEN 0 ELSE peers.failures + 1 END`,
      )
      .run(host, port, now, success ? now : 0, success ? 0 : 1, success ? 1 : 0, success ? 1 : 0);
  }

  /** Known peers, most recently successful first. Ones that keep failing sink. */
  knownPeers(limit = 64): PeerRecord[] {
    const rows = this.#db
      .prepare(
        `SELECT host, port, last_seen, last_success, failures FROM peers
         WHERE failures < 10
         ORDER BY last_success DESC, last_seen DESC LIMIT ?`,
      )
      .all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      host: r.host as string,
      port: Number(r.port),
      lastSeen: Number(r.last_seen),
      lastSuccess: Number(r.last_success),
      failures: Number(r.failures),
    }));
  }

  forgetPeer(host: string, port: number): void {
    this.#db.prepare('DELETE FROM peers WHERE host = ? AND port = ?').run(host, port);
  }

  /* ───────────────────────────────────────────────────────── reports ── */

  stats() {
    const one = (sql: string) => (this.#db.prepare(sql).get() as { n: number }).n;
    return {
      blocks: one('SELECT COUNT(*) AS n FROM blocks'),
      activeBlocks: one('SELECT COUNT(*) AS n FROM blocks WHERE active = 1'),
      utxos: one('SELECT COUNT(*) AS n FROM utxos'),
      contracts: one('SELECT COUNT(*) AS n FROM contracts'),
      undoRecords: one('SELECT COUNT(*) AS n FROM undo'),
      peers: one('SELECT COUNT(*) AS n FROM peers'),
    };
  }
}

function rowToHeader(row: Record<string, unknown>): StoredHeader {
  return {
    hash: row.hash as string,
    prevHash: row.prev_hash as string,
    height: Number(row.height),
    time: Number(row.time),
    bits: Number(row.bits),
    chainWork: BigInt(row.chain_work as string),
    active: Number(row.active) === 1,
  };
}
