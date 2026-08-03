/**
 * Volt — per-commitment secrets and revocation keys.
 *
 * A payment channel updates by replacing state, and old states stay valid
 * transactions forever. The only defence is to make broadcasting an old state
 * catastrophically expensive for the broadcaster. That is what revocation
 * does: when you accept a new commitment, you hand your counterparty the
 * secret that lets them sweep your entire balance out of the *old* one.
 *
 * Two mechanisms, both from BOLT-03, simplified but not weakened:
 *
 *  1. A hash chain of per-commitment secrets. `secret(i) = H^(N-i)(seed)`.
 *     Revealing secret(i) lets the counterparty derive every secret before it
 *     by hashing forward, so storage is O(1) rather than O(commitments).
 *     BOLT-03 uses a 48-bit indexed tree for the same property; the hash
 *     chain is the same idea with a smaller index space.
 *
 *  2. A revocation key that neither party can compute alone. BOLT-03's
 *     construction, unmodified:
 *
 *       h₁ = H(revocationBasepoint ‖ perCommitmentPoint)
 *       h₂ = H(perCommitmentPoint ‖ revocationBasepoint)
 *
 *       revocationPubkey = revocationBasepoint·h₁ + perCommitmentPoint·h₂
 *       revocationSecret = revocationBaseSecret·h₁ + perCommitmentSecret·h₂
 *
 *     Both parties can compute the *public* key from public data, so the
 *     owner can commit to it in its own `to_local` output. Only the
 *     counterparty can ever compute the *private* key, and only once it has
 *     been handed the per-commitment secret — i.e. only after the state has
 *     been revoked.
 *
 *     A hash-based shortcut cannot achieve this. Whoever can hash the inputs
 *     can produce the secret, and the owner knows its own per-commitment
 *     secret from the moment it generates it. The elliptic-curve
 *     homomorphism is load-bearing, so it is used.
 */

import {
  beToBigInt,
  fromHex,
  keyPair,
  pointCombine,
  pointFromSecret,
  scalarCombine,
  taggedHash,
  toHex,
  utf8,
  type Hex,
} from '../crypto.ts';

/** Depth of the secret chain. 4096 updates per channel before a re-anchor is needed. */
export const CHAIN_DEPTH = 4096;

export class SecretChain {
  readonly #seed: Uint8Array;
  readonly depth: number;

  constructor(seed: string, depth = CHAIN_DEPTH) {
    this.#seed = taggedHash('Volt/commitment-seed', utf8(seed));
    this.depth = depth;
  }

  /** Secret for commitment `index`. Lower indexes are derivable from higher ones. */
  secret(index: number): Uint8Array {
    if (index < 0 || index >= this.depth) throw new RangeError('SecretChain: index out of range');
    let h = this.#seed;
    for (let i = 0; i < this.depth - index; i++) h = taggedHash('Volt/chain', h);
    return h;
  }

  secretHex(index: number): Hex {
    return toHex(this.secret(index));
  }

  /** Public per-commitment point. Published with each state; the secret is not. */
  point(index: number): Hex {
    return toHex(pointFromSecret(this.secret(index)));
  }
}

/**
 * Given a revealed secret for commitment `i`, derive the secret for any
 * earlier commitment `j < i`. This is the property that makes the chain
 * storage-efficient — and the property a counterparty relies on when it has
 * to punish a state from 500 updates ago.
 */
export function deriveEarlier(revealed: Uint8Array, from: number, to: number): Uint8Array {
  if (to > from) throw new RangeError('deriveEarlier: can only derive backwards');
  let h = revealed;
  for (let i = 0; i < from - to; i++) h = taggedHash('Volt/chain', h);
  return h;
}

const h1 = (revocationBasepoint: Uint8Array, perCommitmentPoint: Uint8Array): bigint =>
  beToBigInt(taggedHash('Volt/revocation/h1', revocationBasepoint, perCommitmentPoint));

const h2 = (revocationBasepoint: Uint8Array, perCommitmentPoint: Uint8Array): bigint =>
  beToBigInt(taggedHash('Volt/revocation/h2', perCommitmentPoint, revocationBasepoint));

/**
 * Public revocation key for one commitment. Computable by both parties from
 * public data — the owner needs it to build its own `to_local` output.
 */
export function revocationPubkey(
  revocationBasepoint: Hex,
  perCommitmentPoint: Hex,
): Hex {
  const base = fromHex(revocationBasepoint);
  const point = fromHex(perCommitmentPoint);
  return toHex(pointCombine(base, h1(base, point), point, h2(base, point)));
}

/**
 * Private revocation key. Requires the counterparty's revocation base secret
 * *and* the owner's revealed per-commitment secret. Neither party can produce
 * it alone; the owner can never produce it at all.
 */
export function revocationPrivkey(
  revocationBaseSecret: Uint8Array,
  perCommitmentSecret: Uint8Array,
): Uint8Array {
  const base = pointFromSecret(revocationBaseSecret);
  const point = pointFromSecret(perCommitmentSecret);
  return scalarCombine(
    revocationBaseSecret,
    h1(base, point),
    perCommitmentSecret,
    h2(base, point),
  );
}

export function revocationKeyPair(
  revocationBaseSecret: Uint8Array,
  perCommitmentSecret: Uint8Array,
) {
  return keyPair(revocationPrivkey(revocationBaseSecret, perCommitmentSecret));
}
