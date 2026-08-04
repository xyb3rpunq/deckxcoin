/**
 * Schnorr adaptor signatures — the cryptography under PTLCs.
 *
 * An adaptor signature is a signature with a hole in it. It is not valid, and
 * it cannot be made valid without one specific secret scalar `t`. Two things
 * follow, and together they replace the hash lock:
 *
 *   • whoever knows `t` can **complete** the adaptor into a real signature;
 *   • whoever sees the completed signature can **extract** `t` from it.
 *
 * So handing someone an adaptor signature is handing them an offer: *if you
 * publish the secret behind this point, you get a valid signature — and by
 * publishing it, you give the secret to me.* That is exactly the shape of a
 * payment channel hop, and it is why PTLCs can do everything HTLCs do.
 *
 * ── Why this is better than a hash lock ───────────────────────────────────
 * An HTLC locks every hop of a route to `SHA256(preimage)` — the *same* hash at
 * every hop. Two nodes anywhere on the route can compare the hashes they were
 * asked to forward, see they match, and know they are carrying the same
 * payment. That is the strongest deanonymisation primitive Lightning hands out,
 * and it is handed out by construction.
 *
 * With points, the sender gives hop *i* the point `T + r_i·G` for a blinding
 * scalar only the sender knows. Every hop sees a different point. Two colluding
 * hops comparing notes see two unrelated curve points, and correlating them
 * requires solving a discrete log.
 *
 * ── The construction ──────────────────────────────────────────────────────
 *   nonce      R₀ = k·G
 *   adapted    R  = R₀ + T
 *   challenge  e  = H(x(R) ‖ x(P) ‖ m)          — over the *adapted* R
 *   adaptor    s' = k + e·d
 *
 * Verify the adaptor:  s'·G == R₀ + e·P
 * Complete:            s = s' + t   →  (x(R), s) is a valid BIP-340 signature
 * Extract:             t = s − s'
 *
 * The completion works because `s·G = (k + e·d + t)·G = (R₀ + T) + e·P`, which
 * is BIP-340's verification equation with `R = R₀ + T`.
 *
 * ── The parity problem, and why the nonce is ground ───────────────────────
 * BIP-340 signatures carry `R` as an x-coordinate only, and a verifier
 * reconstructs it as the point with **even** Y. But `R = R₀ + T` lands on
 * whichever parity it lands on, and there is no cheap algebraic fix: negating
 * the nonce gives `−R₀ + T`, which is a different point, not `−R`.
 *
 * So the signer grinds. It derives `k` with a counter and retries until
 * `R₀ + T` comes out even. Half of all candidates work, so this costs two
 * point additions on average. It is the boring solution and it is the correct
 * one; the alternative designs all move the problem somewhere it is harder to
 * see.
 */

import {
  CURVE_N,
  beBytes,
  beToBigInt,
  concat,
  fromHex,
  pointFromSecret,
  taggedHash,
  toHex,
  utf8,
  verify,
  type Hex,
  type KeyPair,
} from '../crypto.ts';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const { Point } = secp256k1;

/** How many nonce candidates to try before giving up on an even R. */
const MAX_NONCE_GRIND = 128;

export interface AdaptorSignature {
  /** `R₀ = k·G`, compressed. The nonce *before* the adaptor point is added. */
  readonly nonce: Hex;
  /** `s' = k + e·d`, 32 bytes. Not a valid signature scalar on its own. */
  readonly scalar: Hex;
  /** `T = t·G`, compressed. The point this signature is locked to. */
  readonly point: Hex;
}

/* ─────────────────────────────────────────────────────────── helpers ── */

const mod = (v: bigint): bigint => ((v % CURVE_N) + CURVE_N) % CURVE_N;

function pointOf(hex: Hex) {
  return Point.fromBytes(fromHex(hex));
}

/** BIP-340 challenge: `H_tag("BIP0340/challenge", x(R) ‖ x(P) ‖ m)`. */
function challenge(rx: Uint8Array, px: Uint8Array, message: Uint8Array): bigint {
  return mod(beToBigInt(taggedHash('BIP0340/challenge', rx, px, message)));
}

const xOnly = (p: InstanceType<typeof Point>): Uint8Array => p.toBytes(true).subarray(1);
const hasEvenY = (p: InstanceType<typeof Point>): boolean => p.toBytes(true)[0] === 0x02;

/**
 * The effective private key for BIP-340.
 *
 * A public key is x-only, so it always denotes the even-Y point. If `d·G` has
 * odd Y, the key that actually signs is `n − d`. Forgetting this produces
 * signatures that verify for half of all keys and fail for the other half —
 * the kind of bug that passes a demo and fails in production on a coin flip.
 */
function effectiveKey(privateKey: Uint8Array): { d: bigint; P: InstanceType<typeof Point> } {
  const raw = beToBigInt(privateKey);
  if (raw === 0n || raw >= CURVE_N) throw new Error('adaptor: private key out of range');
  const P = Point.BASE.multiply(raw);
  return hasEvenY(P) ? { d: raw, P } : { d: CURVE_N - raw, P: P.negate() };
}

/** Deterministic nonce, salted with a counter so the signer can grind parity. */
function nonceFor(privateKey: Uint8Array, message: Uint8Array, pointHex: Hex, counter: number): bigint {
  const k = mod(
    beToBigInt(
      taggedHash(
        'DeckxCoin/adaptor-nonce',
        privateKey,
        message,
        fromHex(pointHex),
        Uint8Array.of((counter >> 8) & 0xff, counter & 0xff),
      ),
    ),
  );
  return k === 0n ? 1n : k;
}

/* ────────────────────────────────────────────────────────── the secret ── */

/** A scalar and the point that commits to it. The point is public; the scalar is the payment. */
export interface AdaptorSecret {
  readonly scalar: Hex;
  readonly point: Hex;
}

export function newAdaptorSecret(seed?: string): AdaptorSecret {
  const bytes = seed
    ? taggedHash('DeckxCoin/adaptor-secret', utf8(seed))
    : taggedHash('DeckxCoin/adaptor-secret', crypto.getRandomValues(new Uint8Array(32)));
  const scalar = mod(beToBigInt(bytes)) || 1n;
  const key = beBytes(scalar, 32);
  return { scalar: toHex(key), point: toHex(pointFromSecret(key)) };
}

/** `T = t·G` for a known scalar. */
export function pointForSecret(scalar: Hex): Hex {
  return toHex(pointFromSecret(fromHex(scalar)));
}

/**
 * Blind a point so that a different hop sees a different one.
 *
 * `T' = T + r·G`. The sender knows every `r`, so it can tell each hop what to
 * expect and can undo the blinding when the secret comes back. A hop sees only
 * a curve point, and relating two of them means solving a discrete log.
 */
export function blindPoint(point: Hex, blinding: Hex): Hex {
  const T = pointOf(point);
  const R = Point.BASE.multiply(mod(beToBigInt(fromHex(blinding))));
  return toHex(T.add(R).toBytes(true));
}

/** Undo `blindPoint` on the *scalar* side: `t = t' − r`. */
export function unblindScalar(blinded: Hex, blinding: Hex): Hex {
  const t = mod(beToBigInt(fromHex(blinded)) - beToBigInt(fromHex(blinding)));
  if (t === 0n) throw new Error('unblindScalar: degenerate result');
  return toHex(beBytes(t, 32));
}

/** Apply the blinding to a scalar: `t' = t + r`. */
export function blindScalar(scalar: Hex, blinding: Hex): Hex {
  const t = mod(beToBigInt(fromHex(scalar)) + beToBigInt(fromHex(blinding)));
  if (t === 0n) throw new Error('blindScalar: degenerate result');
  return toHex(beBytes(t, 32));
}

/* ──────────────────────────────────────────────────────────── signing ── */

/**
 * Produce a signature that is worthless until someone supplies `t`.
 *
 * The signer never learns `t` — it only ever sees `T`. That asymmetry is the
 * whole mechanism: the signer is making an offer it cannot itself accept.
 */
export function adaptorSign(message: Uint8Array, key: KeyPair, point: Hex): AdaptorSignature {
  if (message.length !== 32) throw new Error('adaptorSign: message must be a 32-byte digest');

  const { d, P } = effectiveKey(key.privateKey);
  const T = pointOf(point);
  const px = xOnly(P);

  for (let counter = 0; counter < MAX_NONCE_GRIND; counter++) {
    const k = nonceFor(key.privateKey, message, point, counter);
    const R0 = Point.BASE.multiply(k);
    const R = R0.add(T);

    // The verifier will reconstruct R as the even-Y point with this x. If this
    // candidate is odd, no completion of it can ever verify — so try another.
    if (!hasEvenY(R)) continue;

    const e = challenge(xOnly(R), px, message);
    const s = mod(k + e * d);
    if (s === 0n) continue;

    return { nonce: toHex(R0.toBytes(true)), scalar: toHex(beBytes(s, 32)), point };
  }
  throw new Error('adaptorSign: could not find a nonce giving an even adapted point');
}

/**
 * Check an adaptor signature without knowing `t`.
 *
 * This is what a payer runs before parting with anything. It proves the
 * signature *will* be valid the moment the secret appears — so the offer is
 * real, and the only remaining question is whether the counterparty accepts it.
 */
export function adaptorVerify(
  message: Uint8Array,
  adaptor: AdaptorSignature,
  publicKey: Uint8Array,
): boolean {
  try {
    if (message.length !== 32) return false;

    const R0 = pointOf(adaptor.nonce);
    const T = pointOf(adaptor.point);
    const R = R0.add(T);
    if (!hasEvenY(R)) return false;

    // x-only public keys always denote the even-Y point.
    const P = Point.fromBytes(concat(Uint8Array.of(0x02), publicKey.length === 33 ? publicKey.subarray(1) : publicKey));

    const s = beToBigInt(fromHex(adaptor.scalar));
    if (s === 0n || s >= CURVE_N) return false;

    const e = challenge(xOnly(R), xOnly(P), message);
    // s'·G ?= R₀ + e·P
    return Point.BASE.multiply(s).equals(R0.add(P.multiply(e)));
  } catch {
    return false;
  }
}

/**
 * Turn the adaptor into a real signature, using the secret.
 *
 * The result is an ordinary BIP-340 signature — indistinguishable, on-chain,
 * from any other. Nobody looking at it can tell a point lock was involved.
 */
export function adaptorComplete(adaptor: AdaptorSignature, secret: Hex): Hex {
  const t = beToBigInt(fromHex(secret));
  if (t === 0n || t >= CURVE_N) throw new Error('adaptorComplete: secret out of range');

  const T = pointOf(adaptor.point);
  if (!Point.BASE.multiply(t).equals(T)) {
    throw new Error('adaptorComplete: this secret does not open that point');
  }

  const R = pointOf(adaptor.nonce).add(T);
  const s = mod(beToBigInt(fromHex(adaptor.scalar)) + t);
  return toHex(concat(xOnly(R), beBytes(s, 32)));
}

/**
 * Recover the secret from a completed signature.
 *
 * This is the half that makes a route work. When the payee completes and
 * broadcasts, the node before it sees the finished signature, subtracts its own
 * adaptor scalar, and now holds the secret it needs to complete *its* incoming
 * offer. The secret walks backwards along the route, one hop at a time,
 * exactly as an HTLC preimage does — but without a shared identifier.
 */
export function adaptorExtract(signature: Hex, adaptor: AdaptorSignature): Hex {
  const sig = fromHex(signature);
  if (sig.length !== 64) throw new Error('adaptorExtract: signature must be 64 bytes');

  const s = beToBigInt(sig.subarray(32));
  const t = mod(s - beToBigInt(fromHex(adaptor.scalar)));
  if (t === 0n) throw new Error('adaptorExtract: degenerate secret');

  const recovered = toHex(beBytes(t, 32));
  // A signature that did not come from this adaptor yields a scalar that does
  // not open the point. Saying so is better than returning 32 useless bytes.
  if (pointForSecret(recovered) !== adaptor.point) {
    throw new Error('adaptorExtract: that signature did not complete this adaptor');
  }
  return recovered;
}

/** Convenience: does this secret open this point? */
export function opensPoint(secret: Hex, point: Hex): boolean {
  try {
    return pointForSecret(secret) === point;
  } catch {
    return false;
  }
}

/** Re-export so callers can check a completed adaptor with the ordinary verifier. */
export { verify as verifySignature };
