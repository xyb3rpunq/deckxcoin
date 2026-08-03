/**
 * Volt watchtower.
 *
 * The penalty transaction closes the theft loophole in payment channels — but
 * only if somebody broadcasts it. Until now this codebase implemented the
 * penalty and left that "somebody" unspecified, which meant a channel was safe
 * only while its owner was online. For a mobile wallet that is most of the
 * time, and "most" is not a security property.
 *
 * A watchtower removes the liveness requirement. It watches every block for a
 * revoked commitment and publishes the penalty on the victim's behalf.
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
 * the reason it is worth the extra code is that it makes running a tower for
 * strangers safe.
 *
 * ── What this does not do ─────────────────────────────────────────────────
 * No fee bumping: the penalty's fee is fixed when the blob is created, so a
 * fee spike can leave it unconfirmable. No reward mechanism. No persistence —
 * blobs live in memory. All three are stated in the limitations table rather
 * than hidden.
 */

import { concat, fromHex, sha256, taggedHash, toHex, type Hex } from '../crypto.ts';
import { txid, type Transaction } from '../tx.ts';
import type { Block } from '../block.ts';
import { VoltChannel } from './channel.ts';

/** Bytes of the commitment txid used as the lookup hint. */
export const HINT_BYTES = 16;

export interface WatchBlob {
  /** Lookup key: the first `HINT_BYTES` of the commitment txid, hex. */
  readonly hint: Hex;
  /** Encrypted penalty transaction. */
  readonly payload: Hex;
  /** Authenticates the payload before it is parsed. */
  readonly mac: Hex;
  /** Commitment number, so a tower can drop superseded blobs. Not identifying. */
  readonly sequence: number;
}

export interface BreachReport {
  readonly hint: Hex;
  readonly commitmentTxid: Hex;
  readonly height: number;
  readonly penalty: Transaction;
  readonly sweptZaps: bigint;
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
 */
export function sealBlob(commitmentTxid: Hex, penalty: Transaction, sequence: number): WatchBlob {
  const key = encryptionKey(commitmentTxid);
  const plaintext = encoder.encode(JSON.stringify(penalty));
  const payload = xor(plaintext, keystream(key, plaintext.length));
  return {
    hint: commitmentTxid.slice(0, HINT_BYTES * 2),
    payload: toHex(payload),
    mac: toHex(taggedHash('Volt/watchtower/tag', macKey(key), payload)),
    sequence,
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
  readonly broadcast: (tx: Transaction) => boolean;
  /** Blobs retained per hint. Only the newest matters, but keeping a few is cheap. */
  readonly maxBlobsPerHint?: number;
}

export class Watchtower {
  readonly #blobs = new Map<Hex, WatchBlob[]>();
  readonly #broadcast: (tx: Transaction) => boolean;
  readonly #maxPerHint: number;

  readonly breaches: BreachReport[] = [];
  scannedBlocks = 0;

  constructor(opts: WatchtowerOptions) {
    this.#broadcast = opts.broadcast;
    this.#maxPerHint = opts.maxBlobsPerHint ?? 4;
  }

  get blobCount(): number {
    let n = 0;
    for (const list of this.#blobs.values()) n += list.length;
    return n;
  }

  get hintCount(): number {
    return this.#blobs.size;
  }

  /**
   * Accept a blob. The tower cannot tell which channel it belongs to, who the
   * parties are, or how much is at stake.
   */
  register(blob: WatchBlob): void {
    const list = this.#blobs.get(blob.hint) ?? [];
    if (list.some((b) => b.sequence === blob.sequence && b.mac === blob.mac)) return;
    list.push(blob);
    list.sort((a, b) => b.sequence - a.sequence);
    this.#blobs.set(blob.hint, list.slice(0, this.#maxPerHint));
  }

  /**
   * Scan a block for revoked commitments.
   *
   * Returns the penalties broadcast. A hit means someone published a state
   * their counterparty had already revoked — that counterparty now takes the
   * whole channel.
   */
  scanBlock(block: Block): BreachReport[] {
    this.scannedBlocks++;
    const found: BreachReport[] = [];

    for (const tx of block.transactions) {
      const id = txid(tx);
      const hint = id.slice(0, HINT_BYTES * 2);
      const blobs = this.#blobs.get(hint);
      if (!blobs) continue;

      for (const blob of blobs) {
        const penalty = openBlob(id, blob);
        if (!penalty) continue;

        const swept = penalty.outputs.reduce((sum, o) => sum + BigInt(o.value), 0n);
        const report: BreachReport = {
          hint,
          commitmentTxid: id,
          height: block.header.height,
          penalty,
          sweptZaps: swept,
        };

        if (this.#broadcast(penalty)) {
          this.breaches.push(report);
          found.push(report);
          // The channel is closing; nothing else for this hint can matter.
          this.#blobs.delete(hint);
        }
        break;
      }
    }

    return found;
  }

  scanBlocks(blocks: Iterable<Block>): BreachReport[] {
    const all: BreachReport[] = [];
    for (const block of blocks) all.push(...this.scanBlock(block));
    return all;
  }

  /** Forget a channel's blobs, e.g. after a cooperative close. */
  forget(hint: Hex): boolean {
    return this.#blobs.delete(hint);
  }

  stats() {
    return {
      hints: this.hintCount,
      blobs: this.blobCount,
      scannedBlocks: this.scannedBlocks,
      breachesCaught: this.breaches.length,
      sweptZaps: this.breaches.reduce((s, b) => s + b.sweptZaps, 0n).toString(),
    };
  }
}

/* ──────────────────────────────────────────────────────── client ── */

/**
 * Build the blob for a channel state that is about to be revoked.
 *
 * Called by a channel party immediately *before* advancing to the next
 * commitment — at that moment it holds both the old commitment and the
 * revocation material needed to punish it.
 */
export function blobForRevokedState(
  channel: VoltChannel,
  revokedNumber: number,
  cheater: 'a' | 'b',
  sweepTo: string,
  feeZaps = 1000n,
): WatchBlob | undefined {
  const bundle = channel.history[revokedNumber];
  if (!bundle) return undefined;

  const commitment = cheater === 'a' ? bundle.forA : bundle.forB;
  try {
    const penalty = channel.penaltyFor(commitment, revokedNumber, cheater, sweepTo, feeZaps);
    return sealBlob(txid(commitment), penalty, revokedNumber);
  } catch {
    // A commitment whose outputs are all dust cannot be swept profitably.
    return undefined;
  }
}

/**
 * Register blobs for every state a channel has already revoked.
 *
 * The bulk-import path a wallet uses when it first hires a tower.
 */
export function backfill(
  tower: Watchtower,
  channel: VoltChannel,
  cheater: 'a' | 'b',
  sweepTo: string,
  feeZaps = 1000n,
): number {
  let registered = 0;
  for (let n = 0; n < channel.commitmentNumber; n++) {
    const blob = blobForRevokedState(channel, n, cheater, sweepTo, feeZaps);
    if (blob) {
      tower.register(blob);
      registered++;
    }
  }
  return registered;
}
