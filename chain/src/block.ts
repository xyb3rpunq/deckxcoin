/**
 * Blocks and proof-of-work.
 *
 * The header is Bitcoin's, with one addition: `stateRoot`. Bitcoin commits to
 * transactions only; Ethereum commits to transactions *and* the resulting
 * world state, which is what lets a light client be told a contract's storage
 * value and verify it. DeckxCoin carries both commitments in one 8-field
 * header:
 *
 *   version ‖ prevHash ‖ merkleRoot ‖ stateRoot ‖ time ‖ bits ‖ height ‖ nonce
 *
 * Proof-of-work, not proof-of-stake. The whitepaper's argument in §4 is that
 * one-CPU-one-vote is the only way to establish an ordering without a trusted
 * identity registry, and staking reintroduces exactly the "who is allowed to
 * vote" question that PoW dissolves. Nothing since 2008 has invalidated that
 * argument; the objections are about energy, which is a different axis.
 */

import { beBytes, beToBigInt, concat, fromHex, sha256d, toHex, utf8, type Hex } from './crypto.ts';
import { merkleRoot } from './merkle.ts';
import { txid, type Transaction } from './tx.ts';

export interface BlockHeader {
  readonly version: number;
  readonly prevHash: Hex;
  readonly merkleRoot: Hex;
  readonly stateRoot: Hex;
  /** Unix seconds. */
  readonly time: number;
  /** Compact difficulty target, Bitcoin's nBits encoding. */
  readonly bits: number;
  readonly height: number;
  readonly nonce: number;
  /** Extends the search space once `nonce` (32 bits) is exhausted. */
  readonly extraNonce: number;
}

export interface Block {
  readonly header: BlockHeader;
  readonly transactions: readonly Transaction[];
}

/* ------------------------------------------------------- difficulty target */

/**
 * nBits ↔ 256-bit target, Bitcoin's compact float. The top byte is the
 * exponent, the low three bytes the mantissa. Preserved verbatim because
 * every difficulty-adjustment reasoning in the ecosystem is expressed in it.
 */
export function bitsToTarget(bits: number): bigint {
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x007fffff);
  if (exponent <= 3) return mantissa >> BigInt(8 * (3 - exponent));
  return mantissa << BigInt(8 * (exponent - 3));
}

export function targetToBits(target: bigint): number {
  if (target <= 0n) throw new RangeError('targetToBits: target must be positive');
  let size = 0;
  let t = target;
  while (t > 0n) { t >>= 8n; size++; }

  let compact: bigint;
  if (size <= 3) compact = target << BigInt(8 * (3 - size));
  else compact = target >> BigInt(8 * (size - 3));

  // Keep the mantissa's sign bit clear.
  if (compact & 0x00800000n) {
    compact >>= 8n;
    size += 1;
  }
  return Number(compact | (BigInt(size) << 24n));
}

/**
 * Genesis difficulty. Deliberately mineable in well under a second on a
 * laptop: this chain is a reference implementation and a live demo, and a
 * genesis block nobody can reproduce is a genesis block nobody can audit.
 * Mainnet parameters would set this to 0x1d00ffff, Bitcoin's own.
 */
export const GENESIS_BITS = 0x1f00ffff;
export const MAX_TARGET = bitsToTarget(GENESIS_BITS);

/** Ten minutes, for the same reason Bitcoin picked it: block propagation ≪ block interval. */
export const TARGET_SPACING = 600;
/** Retarget every 2016 blocks ≈ two weeks. */
export const RETARGET_INTERVAL = 2016;
export const TARGET_TIMESPAN = RETARGET_INTERVAL * TARGET_SPACING;

/**
 * Difficulty retarget. Clamped to a 4× move per period in either direction —
 * without the clamp, a single manipulated timestamp span can drive difficulty
 * to a value the network cannot climb back out of.
 */
export function nextBits(currentBits: number, actualTimespan: number): number {
  const clamped = Math.min(
    Math.max(actualTimespan, Math.floor(TARGET_TIMESPAN / 4)),
    TARGET_TIMESPAN * 4,
  );
  const target = bitsToTarget(currentBits);
  let next = (target * BigInt(clamped)) / BigInt(TARGET_TIMESPAN);
  if (next > MAX_TARGET) next = MAX_TARGET;
  return targetToBits(next);
}

/* ---------------------------------------------------------- header hashing */

export function serializeHeader(h: BlockHeader): Uint8Array {
  return concat(
    beBytes(BigInt(h.version), 4),
    fromHex(h.prevHash),
    fromHex(h.merkleRoot),
    fromHex(h.stateRoot),
    beBytes(BigInt(h.time), 8),
    beBytes(BigInt(h.bits >>> 0), 4),
    beBytes(BigInt(h.height), 4),
    beBytes(BigInt(h.nonce >>> 0), 4),
    beBytes(BigInt(h.extraNonce >>> 0), 4),
  );
}

/** Block hash = double-SHA256 of the 88-byte header. */
export function blockHash(h: BlockHeader): Hex {
  return toHex(sha256d(serializeHeader(h)));
}

export function meetsTarget(hash: Hex, bits: number): boolean {
  return beToBigInt(fromHex(hash)) <= bitsToTarget(bits);
}

/** Chainwork contributed by one header: 2^256 / (target+1). Sums to the honest-chain selector. */
export function blockWork(bits: number): bigint {
  const target = bitsToTarget(bits);
  return (1n << 256n) / (target + 1n);
}

/* ------------------------------------------------------------------ mining */

export interface MineResult {
  readonly header: BlockHeader;
  readonly hash: Hex;
  readonly attempts: number;
  readonly elapsedMs: number;
}

/**
 * Grind nonce → extraNonce until the header hash is under target.
 *
 * Single-threaded and honest about it: this is the reference miner used by
 * the tests and the genesis ceremony, not a competitive one.
 *
 * @param maxAttempts safety valve so a mis-set difficulty cannot hang CI.
 */
export function mine(header: BlockHeader, maxAttempts = 50_000_000): MineResult {
  const started = Date.now();
  let nonce = header.nonce >>> 0;
  let extraNonce = header.extraNonce >>> 0;

  for (let attempts = 1; attempts <= maxAttempts; attempts++) {
    const candidate: BlockHeader = { ...header, nonce, extraNonce };
    const hash = blockHash(candidate);
    if (meetsTarget(hash, header.bits)) {
      return { header: candidate, hash, attempts, elapsedMs: Date.now() - started };
    }
    nonce = (nonce + 1) >>> 0;
    if (nonce === 0) extraNonce = (extraNonce + 1) >>> 0;
  }
  throw new Error(`mine: no solution within ${maxAttempts} attempts`);
}

/* -------------------------------------------------------------- block rules */

/* ------------------------------------------------------- monetary policy */

/**
 * DeckxCoin's issuance schedule: **21,000,000 DECKX cap, halving once a year.**
 *
 * Bitcoin halves every 210,000 blocks ≈ 4 years. DeckxCoin halves every
 * **365 days**, which at 600-second spacing is exactly
 *
 *     365 days × 24 h × 6 blocks/h = 52,560 blocks
 *
 * The initial subsidy is then **not a free choice** — the cap and the interval
 * over-determine it. A geometric halving series sums to `2 × interval ×
 * subsidy`, so:
 *
 *     INITIAL_SUBSIDY = ⌊ 2,100,000,000,000,000 zaps / (2 × 52,560) ⌋
 *                     = 19,977,168,949 zaps
 *                     = 199.77168949 DECKX
 *
 * That number is ugly, and it is ugly for a good reason: it is derived, not
 * picked. Rounding it up to 200 DECKX would issue 21,024,000 DECKX — over the
 * cap — and would then need a special-cased final era to clip the excess. A
 * cliff in the issuance curve is a consensus edge case nobody tests. This way
 * the series lands under the cap on its own, exactly as Bitcoin's does.
 *
 * Verified in `test/primitives.test.ts` by summing all 64 eras.
 *
 * ── Consequence, stated honestly ──────────────────────────────────────────
 * A 1-year halving front-loads issuance hard. ~50 % of supply exists after one
 * year, ~99.9 % after ten. Bitcoin reaches the same point around 2140. This
 * chain therefore transitions from a subsidy-funded security budget to a
 * fee-funded one roughly an order of magnitude faster, and any real
 * deployment must have a working fee market long before that. It is a design
 * choice with a real cost, not a free upgrade.
 */
export const ZAPS_PER_COIN = 100_000_000n;

/** 21,000,000 DECKX, in zaps. The hard ceiling. */
export const MAX_SUPPLY = 21_000_000n * ZAPS_PER_COIN;

/** 365 days at 600-second spacing. */
export const HALVING_INTERVAL = 52_560;

/** Derived from `MAX_SUPPLY` and `HALVING_INTERVAL` — see the note above. */
export const INITIAL_SUBSIDY = MAX_SUPPLY / (2n * BigInt(HALVING_INTERVAL));

/** After this many halvings the subsidy is zero regardless of arithmetic. */
export const MAX_HALVINGS = 64;

export function blockSubsidy(height: number): bigint {
  if (height < 0) throw new RangeError('blockSubsidy: negative height');
  const halvings = Math.floor(height / HALVING_INTERVAL);
  if (halvings >= MAX_HALVINGS) return 0n;
  return INITIAL_SUBSIDY >> BigInt(halvings);
}

/**
 * Total coins issued up to and including `height`.
 *
 * Closed form rather than a loop: within era *e* every block pays
 * `INITIAL_SUBSIDY >> e`, so the sum is a handful of multiplications no matter
 * how tall the chain is. A node auditing supply at height 10,000,000 should
 * not have to iterate ten million times.
 */
export function cumulativeIssuance(height: number): bigint {
  let total = 0n;
  const fullEras = Math.min(Math.floor((height + 1) / HALVING_INTERVAL), MAX_HALVINGS);
  for (let era = 0; era < fullEras; era++) {
    total += BigInt(HALVING_INTERVAL) * (INITIAL_SUBSIDY >> BigInt(era));
  }
  const remainder = height + 1 - fullEras * HALVING_INTERVAL;
  if (remainder > 0 && fullEras < MAX_HALVINGS) {
    total += BigInt(remainder) * (INITIAL_SUBSIDY >> BigInt(fullEras));
  }
  return total;
}

/** Height at which the last non-zero subsidy is paid. */
export function terminalHeight(): number {
  for (let era = 0; era < MAX_HALVINGS; era++) {
    if ((INITIAL_SUBSIDY >> BigInt(era)) === 0n) return era * HALVING_INTERVAL - 1;
  }
  return MAX_HALVINGS * HALVING_INTERVAL - 1;
}

export const MAX_BLOCK_TXS = 4096;
/** Total DVM gas a single block may consume. */
export const BLOCK_GAS_LIMIT = 30_000_000;
/** A header's timestamp may not exceed local time by more than this. */
export const MAX_FUTURE_DRIFT = 2 * 60 * 60;

export function computeMerkleRoot(txs: readonly Transaction[]): Hex {
  return merkleRoot(txs.map(txid));
}

/**
 * Header-only validation: proof of work, transaction commitment, sane
 * timestamp. State validity is checked by the chain, which owns the UTXO set.
 */
export function checkHeader(
  block: Block,
  now: number = Math.floor(Date.now() / 1000),
): { ok: boolean; error?: string } {
  const { header, transactions } = block;

  if (transactions.length === 0) return { ok: false, error: 'block has no transactions' };
  if (transactions.length > MAX_BLOCK_TXS) return { ok: false, error: 'too many transactions' };
  if (transactions[0].kind !== 'coinbase') return { ok: false, error: 'first transaction must be coinbase' };
  if (transactions.slice(1).some((t) => t.kind === 'coinbase')) {
    return { ok: false, error: 'more than one coinbase' };
  }

  const expected = computeMerkleRoot(transactions);
  if (expected !== header.merkleRoot) {
    return { ok: false, error: `merkle root mismatch: header ${header.merkleRoot} vs computed ${expected}` };
  }

  if (header.time > now + MAX_FUTURE_DRIFT) return { ok: false, error: 'block timestamp too far in the future' };

  const hash = blockHash(header);
  if (!meetsTarget(hash, header.bits)) return { ok: false, error: `insufficient proof of work: ${hash}` };

  return { ok: true };
}

/** The message embedded in the genesis coinbase — DeckxCoin's "Chancellor on brink" line. */
export const GENESIS_MEMO =
  'REKT 02/Aug/2026 Every exit liquidity was once someone conviction';

export const GENESIS_MEMO_BYTES = utf8(GENESIS_MEMO).length;
