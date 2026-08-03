/**
 * Compact block relay.
 *
 * Sending a whole block to every peer wastes almost all of the bandwidth,
 * because a peer that has been running for more than a few seconds already
 * holds most of the block's transactions in its mempool. It asked for them
 * once; sending them again inside a block is pure duplication.
 *
 * Instead a node announces a block as:
 *
 *     header ‖ nonce ‖ short id per transaction ‖ a few prefilled transactions
 *
 * The receiver matches the short ids against its own mempool, and asks only
 * for the ones it is missing. On a healthy network that is usually zero, and a
 * block that would have been hundreds of kilobytes crosses the wire as a few.
 *
 * ── Why this matters beyond bandwidth ─────────────────────────────────────
 * Propagation delay is the window in which two miners can both find a block at
 * the same height. Shortening it directly reduces the orphan rate, which
 * directly reduces how much hash power is wasted — and wasted hash power is
 * hash power not defending the chain. Bitcoin adopted this as BIP-152 for
 * exactly that reason.
 *
 * ── Short ids, and why they are salted ────────────────────────────────────
 * A short id is six bytes of a keyed hash of the transaction id. Six bytes
 * invites collisions — with a few thousand transactions the birthday bound is
 * not comfortable — so the key is derived from the block header *and a nonce
 * the sender picks fresh for every announcement*.
 *
 * That salting is the whole defence. An attacker who could predict the short
 * id of a transaction could craft a different transaction sharing it, and the
 * receiver would reconstruct a block that fails its Merkle check — wasting a
 * round trip every block, forever. Because the salt is unpredictable and
 * per-announcement, no such transaction can be prepared in advance, and a
 * collision that does occur is a one-off that the reconstruction check
 * catches.
 */

import { concat, fromHex, sha256, taggedHash, toHex, type Hex } from '../crypto.ts';
import { blockHash, MAX_BLOCK_TXS, serializeHeader, type Block, type BlockHeader } from '../block.ts';
import { txid, type Transaction } from '../tx.ts';

/** Bytes of the keyed hash used as a short id. */
export const SHORT_ID_BYTES = 6;

/**
 * Announcements a node will hold while waiting for missing transactions.
 * Bounded, because each one pins a header and a list in memory.
 */
export const MAX_PENDING_COMPACT = 16;

export interface CompactBlock {
  readonly header: BlockHeader;
  /** Fresh per announcement. Salts the short ids so they cannot be predicted. */
  readonly nonce: string;
  /** Six-byte ids, hex, in block order — excluding the prefilled ones. */
  readonly shortIds: readonly Hex[];
  /**
   * Transactions sent in full. The coinbase always, because no peer can have
   * it in a mempool, plus anything the sender knows is unlikely to be shared.
   */
  readonly prefilled: ReadonlyArray<{ index: number; transaction: Transaction }>;
}

export interface BlockTxnRequest {
  readonly blockHash: Hex;
  /** Positions in the block, ascending. */
  readonly indexes: readonly number[];
}

export interface BlockTxnResponse {
  readonly blockHash: Hex;
  readonly transactions: readonly Transaction[];
}

/* ─────────────────────────────────────────────────────────── short ids ── */

/**
 * Derive the per-announcement key.
 *
 * Both the header and the nonce go in, so two announcements of the same block
 * by different peers produce different short ids — and an attacker cannot
 * precompute against either.
 */
function shortIdKey(header: BlockHeader, nonce: string): Uint8Array {
  return taggedHash('DeckxCoin/compact/v1', serializeHeader(header), fromHex(nonce));
}

/** Six bytes of a keyed hash over the transaction id. */
export function shortId(key: Uint8Array, id: Hex): Hex {
  return toHex(sha256(concat(key, fromHex(id))).subarray(0, SHORT_ID_BYTES));
}

/** Fresh 8-byte salt. */
export function compactNonce(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/* ──────────────────────────────────────────────────────────── encoding ── */

/**
 * Build a compact announcement.
 *
 * The coinbase is always prefilled: it is created by this block and cannot be
 * in anybody's mempool, so a short id for it would always miss and cost a
 * round trip.
 */
export function toCompact(block: Block, nonce = compactNonce()): CompactBlock {
  const key = shortIdKey(block.header, nonce);
  const shortIds: Hex[] = [];
  const prefilled: Array<{ index: number; transaction: Transaction }> = [];

  block.transactions.forEach((tx, index) => {
    if (index === 0) {
      prefilled.push({ index, transaction: tx });
      return;
    }
    shortIds.push(shortId(key, txid(tx)));
  });

  return { header: block.header, nonce, shortIds, prefilled };
}

export interface Reconstruction {
  readonly ok: boolean;
  readonly error?: string;
  readonly block?: Block;
  /** Positions the receiver could not fill. Empty means the block is complete. */
  readonly missing: readonly number[];
  /** How many came from the mempool rather than the wire. */
  readonly fromMempool: number;
}

/**
 * Try to rebuild a block from a compact announcement and a pool of candidates.
 *
 * Returns the positions it could not fill rather than failing, so the caller
 * can ask for exactly those. A returned block is *not* yet validated — that is
 * the chain's job, and it is what catches a short-id collision that slipped
 * through.
 */
export function reconstruct(
  compact: CompactBlock,
  available: Iterable<Transaction>,
  extra: Iterable<Transaction> = [],
): Reconstruction {
  if (!compact?.header || !Array.isArray(compact.shortIds)) {
    return { ok: false, error: 'malformed compact block', missing: [], fromMempool: 0 };
  }

  const key = shortIdKey(compact.header, compact.nonce);

  // Index every candidate by its short id under this announcement's salt.
  const bySortId = new Map<Hex, Transaction>();
  const index = (tx: Transaction) => {
    try {
      bySortId.set(shortId(key, txid(tx)), tx);
    } catch {
      /* A malformed candidate simply does not match anything. */
    }
  };
  for (const tx of available) index(tx);
  for (const tx of extra) index(tx);

  /*
   * The slot count is defined by the announcement itself, so it cannot be
   * "wrong" relative to its own contents — but it *is* attacker-controlled, so
   * it still needs a ceiling. Everything below is checked against the block
   * limit and against the announcement's internal consistency; the final word
   * on whether the reconstruction is the real block belongs to the Merkle
   * commitment, checked by the chain.
   */
  const total = compact.shortIds.length + compact.prefilled.length;
  if (total === 0) {
    return { ok: false, error: 'compact block announces no transactions', missing: [], fromMempool: 0 };
  }
  if (total > MAX_BLOCK_TXS) {
    return {
      ok: false,
      error: `compact block announces ${total} transactions, over the ${MAX_BLOCK_TXS} limit`,
      missing: [],
      fromMempool: 0,
    };
  }

  const slots: Array<Transaction | undefined> = new Array(total);

  for (const entry of compact.prefilled) {
    if (!Number.isInteger(entry?.index) || entry.index < 0 || entry.index >= total) {
      return { ok: false, error: `prefilled index ${entry?.index} is out of range`, missing: [], fromMempool: 0 };
    }
    if (slots[entry.index] !== undefined) {
      return { ok: false, error: `prefilled index ${entry.index} appears twice`, missing: [], fromMempool: 0 };
    }
    slots[entry.index] = entry.transaction;
  }

  // Walk the short ids into the gaps the prefilled transactions left.
  const missing: number[] = [];
  let fromMempool = 0;
  let cursor = 0;

  for (const id of compact.shortIds) {
    while (cursor < total && slots[cursor] !== undefined) cursor++;
    // Unreachable by construction — `total` counts both lists — but a bad
    // announcement should fail loudly rather than write past the array.
    if (cursor >= total) {
      return { ok: false, error: 'short ids do not fit the announced slots', missing: [], fromMempool: 0 };
    }
    const found = bySortId.get(id);
    if (found) {
      slots[cursor] = found;
      fromMempool++;
    } else {
      missing.push(cursor);
    }
    cursor++;
  }

  if (missing.length > 0) return { ok: false, missing, fromMempool };

  return {
    ok: true,
    block: { header: compact.header, transactions: slots as Transaction[] },
    missing: [],
    fromMempool,
  };
}

/**
 * Fill the gaps a first reconstruction left, using transactions from the peer.
 *
 * Takes the original candidate pool as well as the supplied transactions. The
 * first version did not, and re-ran reconstruction against the two or three
 * transactions the peer had just sent — reporting everything the mempool had
 * already supplied as missing all over again.
 */
export function fillMissing(
  compact: CompactBlock,
  partial: Reconstruction,
  supplied: readonly Transaction[],
  available: Iterable<Transaction> = [],
): Reconstruction {
  if (partial.missing.length !== supplied.length) {
    return {
      ok: false,
      error: `asked for ${partial.missing.length} transactions, peer sent ${supplied.length}`,
      missing: partial.missing,
      fromMempool: partial.fromMempool,
    };
  }
  return reconstruct(compact, available, supplied);
}

/**
 * How much a compact announcement saved.
 *
 * Reported honestly: the short-id list and prefilled transactions are counted,
 * not just the header.
 */
export function savings(block: Block, compact: CompactBlock): {
  fullBytes: number;
  compactBytes: number;
  ratio: number;
} {
  const fullBytes = JSON.stringify(block).length;
  const compactBytes = JSON.stringify(compact).length;
  return { fullBytes, compactBytes, ratio: compactBytes / fullBytes };
}

export const compactBlockHash = (compact: CompactBlock): Hex => blockHash(compact.header);
