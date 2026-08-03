/**
 * Network parameters.
 *
 * Three networks, one codebase. Everything that differs between them lives
 * here, and nothing else may branch on network identity — the moment
 * consensus code contains `if (network === 'testnet')`, the testnet stops
 * testing mainnet.
 *
 * What legitimately differs:
 *   • proof-of-work target (so a laptop can mine testnet)
 *   • genesis seed / message / timestamp (so chains cannot be confused)
 *   • wire magic (so a testnet node cannot accidentally peer with mainnet)
 *   • default ports
 *
 * What does not differ, ever: the 21 M cap, the 365-day halving, the coinbase
 * maturity, the covenant rule, the signature scheme, the state root.
 */

import { GENESIS_BITS, GENESIS_MEMO } from './block.ts';
import { GENESIS_SEED, GENESIS_TIME, REGTEST_BITS } from './chain.ts';

export interface NetworkParams {
  readonly name: string;
  /** Proof-of-work target for genesis, in compact nBits form. */
  readonly bits: number;
  readonly genesisSeed: string;
  readonly genesisMemo: string;
  readonly genesisTime: number;
  /**
   * Four-byte prefix on every wire message. Its only job is to make a
   * cross-network connection fail loudly on the first frame instead of
   * subtly, ten blocks later.
   */
  readonly magic: number;
  readonly defaultPort: number;
  readonly defaultRpcPort: number;
  /** Hosts a fresh node dials when it knows no peers. */
  readonly seeds: readonly string[];
}

export const MAINNET: NetworkParams = {
  name: 'mainnet',
  bits: GENESIS_BITS,
  genesisSeed: GENESIS_SEED,
  genesisMemo: GENESIS_MEMO,
  genesisTime: GENESIS_TIME,
  magic: 0xd3c4c015,
  defaultPort: 9333,
  defaultRpcPort: 9332,
  seeds: [],
};

/**
 * Public testnet. Same rules, easier work, so blocks arrive without a farm.
 * `0x1e00ffff` is ~2^-8 harder than regtest and ~2^8 easier than mainnet —
 * enough that a block still takes measurable work, little enough that a single
 * laptop keeps a chain moving.
 */
export const TESTNET: NetworkParams = {
  name: 'testnet',
  bits: 0x1e00ffff,
  genesisSeed: 'deckxcoin/testnet/rekt',
  genesisMemo: 'REKT testnet 03/Aug/2026 Nothing here is worth anything',
  genesisTime: 1_785_715_200,
  magic: 0xd3c4c716,
  defaultPort: 19333,
  defaultRpcPort: 19332,
  seeds: [],
};

/** Local development. Every hash wins, so tests exercise consensus not CPU. */
export const REGTEST: NetworkParams = {
  name: 'regtest',
  bits: REGTEST_BITS,
  genesisSeed: 'deckxcoin/regtest',
  genesisMemo: 'REKT regtest',
  genesisTime: GENESIS_TIME,
  magic: 0xd3c4facc,
  defaultPort: 29333,
  defaultRpcPort: 29332,
  seeds: [],
};

export const NETWORKS: Record<string, NetworkParams> = {
  mainnet: MAINNET,
  testnet: TESTNET,
  regtest: REGTEST,
};

export function networkByName(name: string): NetworkParams {
  const params = NETWORKS[name];
  if (!params) {
    throw new Error(`unknown network '${name}' — expected one of ${Object.keys(NETWORKS).join(', ')}`);
  }
  return params;
}

/* ─────────────────────────────────────────────────────────── node limits ── */

/** Outbound connections a node maintains. Bitcoin uses 8; so do we. */
export const MAX_OUTBOUND_PEERS = 8;
/** Inbound connections accepted before new ones are refused. */
export const MAX_INBOUND_PEERS = 32;
/** Headers returned by a single `headers` message. */
export const MAX_HEADERS_PER_MESSAGE = 2000;
/** Inventory entries in a single `inv`. */
export const MAX_INV_PER_MESSAGE = 500;
/** Largest wire message accepted, in bytes. Anything larger is a resource attack. */
export const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
/** Ban score at which a peer is disconnected and blocked. */
export const BAN_THRESHOLD = 100;
/** Seconds of silence before a peer is pinged. */
export const PING_INTERVAL = 30;
/** Seconds without a pong before the peer is dropped. */
export const PEER_TIMEOUT = 120;
/** Undo records kept. Bounds a reorg's depth and the database's size. */
export const UNDO_RETENTION = 500;
