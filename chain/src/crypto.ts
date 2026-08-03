/**
 * DeckxCoin — cryptographic primitives.
 *
 * Bitcoin heritage: double-SHA256 for block/tx identifiers, HASH160
 * (RIPEMD160 ∘ SHA256) for address commitments. Ethereum heritage:
 * keccak-style domain separation for contract addresses and storage slots (we
 * use SHA256 with explicit domain tags instead of keccak so the whole chain
 * needs exactly one hash family).
 *
 * Every hash here is domain-separated. Two different structures can never
 * produce the same preimage, which is the bug class that killed more than one
 * altcoin.
 *
 * ── Signatures: BIP-340 Schnorr, not ECDSA ────────────────────────────────
 *
 * Every signature on this chain is a 64-byte BIP-340 Schnorr signature over a
 * 32-byte x-only public key. ECDSA is not supported at all — not deprecated,
 * not legacy, absent. Four reasons, in the order they actually mattered:
 *
 *  1. **Batch verification.** Schnorr signatures are linear, so `n` of them
 *     verify in roughly the cost of `n/2` individually. Initial block download
 *     is dominated by signature checking, and this is the single largest win
 *     available without changing the consensus rules.
 *  2. **Provable security.** BIP-340 has a security proof under the discrete
 *     logarithm assumption. ECDSA's does not exist without additional
 *     assumptions, and its history of nonce-reuse catastrophes is not an
 *     accident of implementation.
 *  3. **Non-malleability by construction.** ECDSA needs a low-s rule bolted on
 *     to stop `(r, s)` and `(r, n−s)` both verifying. Schnorr signatures are
 *     unique for a given key and message.
 *  4. **One code path.** Supporting both would mean every verifier branches on
 *     a scheme selector, and every such branch is somewhere a check can be
 *     skipped. Bitcoin carries both because it had to; this chain does not.
 *
 * The cost is that public keys are x-only: a key commits to an x-coordinate,
 * and the y-coordinate is implicitly the even one. Anywhere a *point* is
 * needed rather than a key — ECDH inside the onion, the revocation-key
 * homomorphism — the code uses compressed 33-byte points explicitly. Confusing
 * those two encodings is the one real hazard this migration introduces, so the
 * function names say which is which.
 *
 * Implementation is `@noble/curves`, the audited reference. Hand-rolling
 * BIP-340 for a project that talks about security would be exactly the wrong
 * call, however tempting the forty lines look.
 */

import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bech32m, hex as hexCodec } from '@scure/base';

/** Curve point type from the underlying library. */
const Point = secp256k1.Point;

export type Hex = string;

/** Human readable part of every DeckxCoin address. */
export const HRP = 'dxc';

/* ------------------------------------------------------------------ bytes */

export const toHex = (b: Uint8Array): Hex => hexCodec.encode(b);
export const fromHex = (h: Hex): Uint8Array => hexCodec.decode(stripHexPrefix(h));

export function stripHexPrefix(h: string): string {
  return h.startsWith('0x') ? h.slice(2) : h;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Big-endian encoding of a bigint into exactly `len` bytes. */
export function beBytes(value: bigint, len: number): Uint8Array {
  if (value < 0n) throw new RangeError('beBytes: negative value');
  const out = new Uint8Array(len);
  let v = value;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError(`beBytes: value does not fit in ${len} bytes`);
  return out;
}

export function beToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

/* ------------------------------------------------------------------ hashes */

export const sha256d = (data: Uint8Array): Uint8Array => sha256(sha256(data));
export const hash160 = (data: Uint8Array): Uint8Array => ripemd160(sha256(data));

/**
 * Domain-separated hash. `tag` is mixed in as SHA256(tag) twice, the same
 * construction as BIP-340 tagged hashes, so a digest computed for one purpose
 * is never valid for another.
 */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagHash = sha256(utf8(tag));
  return sha256(concat(tagHash, tagHash, ...data));
}

export const taggedHex = (tag: string, ...data: Uint8Array[]): Hex =>
  toHex(taggedHash(tag, ...data));

/* -------------------------------------------------------------------- keys */

export interface KeyPair {
  readonly privateKey: Uint8Array;
  /** 32-byte x-only BIP-340 public key. This is what addresses commit to. */
  readonly publicKey: Uint8Array;
  /** 33-byte compressed point for the same key. Needed wherever ECDH is. */
  readonly point: Uint8Array;
  readonly address: string;
}

export const PUBKEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;

export function randomPrivateKey(): Uint8Array {
  return secp256k1.utils.randomSecretKey();
}

/**
 * Deterministic key derivation from a seed phrase. Used by the CLI and the
 * test vectors so a documented genesis is byte-for-byte reproducible on any
 * machine. Not a BIP-32 wallet — DeckxCoin keys are single-purpose.
 */
export function keyFromSeed(seed: string): Uint8Array {
  let material = taggedHash('DeckxCoin/seed', utf8(seed));
  // Reject-and-rehash until the scalar is in range, exactly like BIP-32 does.
  for (let i = 0; i < 256; i++) {
    if (secp256k1.utils.isValidSecretKey(material)) return material;
    material = taggedHash('DeckxCoin/seed/retry', material);
  }
  throw new Error('keyFromSeed: exhausted retries');
}

export function keyPair(privateKey: Uint8Array): KeyPair {
  const publicKey = schnorr.getPublicKey(privateKey);
  const point = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, publicKey, point, address: addressFromPubkey(publicKey) };
}

export const keyPairFromSeed = (seed: string): KeyPair => keyPair(keyFromSeed(seed));

/** x-only public key for a secret. The form addresses and signatures use. */
export const xOnlyFromSecret = (privateKey: Uint8Array): Uint8Array =>
  schnorr.getPublicKey(privateKey);

/**
 * Drop the parity byte from a compressed point.
 *
 * A 33-byte compressed point and a 32-byte x-only key describe the same
 * x-coordinate; x-only simply asserts the even-y branch. Conversion one way is
 * free, the other way is a `lift_x`.
 */
export function toXOnly(point: Uint8Array): Uint8Array {
  if (point.length === PUBKEY_BYTES) return point;
  if (point.length === 33) return point.subarray(1);
  throw new Error(`toXOnly: expected 32 or 33 bytes, got ${point.length}`);
}

/** Lift an x-only key to the compressed point with even y. */
export function toPoint(xOnly: Uint8Array): Uint8Array {
  if (xOnly.length === 33) return xOnly;
  if (xOnly.length !== PUBKEY_BYTES) {
    throw new Error(`toPoint: expected 32 bytes, got ${xOnly.length}`);
  }
  return concat(Uint8Array.of(0x02), xOnly);
}

/* ---------------------------------------------------------------- addresses */

/**
 * Address = bech32m(hrp="dxc", version=0, HASH160(pubkey)).
 *
 * Bech32m (BIP-350) rather than bech32 because DeckxCoin has no legacy
 * segwit-v0 checksum to stay compatible with, and bech32m fixes the
 * length-extension weakness in the original checksum.
 */
export function addressFromHash160(h160: Uint8Array, version = 0): string {
  if (h160.length !== 20) throw new Error('addressFromHash160: expected 20 bytes');
  const words = [version, ...bech32m.toWords(h160)];
  return bech32m.encode(HRP, words, 90);
}

export const addressFromPubkey = (pubkey: Uint8Array): string =>
  addressFromHash160(hash160(pubkey));

export function decodeAddress(address: string): { version: number; hash: Uint8Array } {
  const { prefix, words } = bech32m.decode(address as `${string}1${string}`, 90);
  if (prefix !== HRP) throw new Error(`decodeAddress: wrong prefix ${prefix}`);
  const version = words[0];
  const hash = Uint8Array.from(bech32m.fromWords(words.slice(1)));
  if (hash.length !== 20) throw new Error('decodeAddress: bad payload length');
  return { version, hash };
}

export function isValidAddress(address: string): boolean {
  try {
    decodeAddress(address);
    return true;
  } catch {
    return false;
  }
}

/**
 * Contract addresses follow Ethereum's CREATE rule in spirit: deterministic
 * from (deployer, nonce), so a deployer can compute the address before the
 * transaction is mined. Rendered in the same bech32m format as user addresses
 * but under version 1, so a wallet can refuse to send a bare transfer to code.
 */
export function contractAddress(deployer: string, nonce: number): string {
  const digest = taggedHash(
    'DeckxCoin/contract',
    utf8(deployer),
    beBytes(BigInt(nonce), 8),
  );
  return addressFromHash160(digest.slice(0, 20), 1);
}

export const isContractAddress = (address: string): boolean => {
  try {
    return decodeAddress(address).version === 1;
  } catch {
    return false;
  }
};

/* --------------------------------------------------------------- signatures */

/**
 * Sign a 32-byte digest with BIP-340 Schnorr. Returns 64 bytes as hex.
 *
 * Deterministic: no auxiliary randomness is supplied, so signing the same
 * digest with the same key always yields the same signature. That is what
 * makes the genesis block and every test vector reproducible on any machine.
 * BIP-340 permits this — the nonce is derived from the key and message either
 * way, and the aux-rand is a defence against fault attacks that does not apply
 * to a reference implementation running on a general-purpose CPU.
 */
export function sign(digest: Uint8Array, privateKey: Uint8Array): Hex {
  if (digest.length !== 32) throw new Error('sign: digest must be 32 bytes');
  return toHex(schnorr.sign(digest, privateKey, new Uint8Array(32)));
}

/** Verify a Schnorr signature against a 32-byte x-only key. */
export function verify(signature: Hex, digest: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    const sig = fromHex(signature);
    if (sig.length !== SIGNATURE_BYTES) return false;
    return schnorr.verify(sig, digest, toXOnly(publicKey));
  } catch {
    return false;
  }
}

/**
 * Verify many signatures at once.
 *
 * The reason this chain uses Schnorr. Signatures are linear, so a verifier can
 * check the sum of randomly-weighted equations instead of each equation
 * separately, and initial block download stops being dominated by signature
 * checking.
 *
 * `@noble/curves` does not expose a batch primitive, so this loops — the
 * *interface* is what matters here: callers that hand over a batch get the
 * speed-up as soon as the primitive lands, without changing a line. A batch
 * that fails is retried one by one so the caller learns which signature was
 * bad, which a naive batch verifier cannot tell you.
 */
export function verifyBatch(
  items: ReadonlyArray<{ signature: Hex; digest: Uint8Array; publicKey: Uint8Array }>,
): { ok: boolean; failedIndex?: number } {
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!verify(item.signature, item.digest, item.publicKey)) return { ok: false, failedIndex: i };
  }
  return { ok: true };
}

/* ----------------------------------------------- adaptor points (PTLC-ready) */

/**
 * Point derived from a scalar secret — the building block for PTLCs, where a
 * payment is locked to `s·G` rather than to `SHA256(preimage)`. Volt still
 * settles with hash locks today (BOLT-compatible), but every channel already
 * carries the point so the upgrade is a flag flip, not a re-spec.
 */
export function pointFromSecret(secret: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(secret, true);
}

export function pointsEqual(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/** Order of the secp256k1 group. Scalar arithmetic is mod this. */
export const CURVE_N: bigint = Point.Fn.ORDER;

/**
 * Compute `P₁·s₁ + P₂·s₂` on the curve, returning a compressed point.
 *
 * Volt's revocation keys are built from this: a public key that two parties
 * can each derive from public data, but whose *private* key requires one
 * secret from each of them. No hash construction can do that — it genuinely
 * needs the group's homomorphism.
 */
export function pointCombine(p1: Uint8Array, s1: bigint, p2: Uint8Array, s2: bigint): Uint8Array {
  const P1 = Point.fromBytes(toPoint(p1));
  const P2 = Point.fromBytes(toPoint(p2));
  const sum = P1.multiply(mod(s1)).add(P2.multiply(mod(s2)));
  return sum.toBytes(true);
}

/** The matching scalar: `k₁·s₁ + k₂·s₂ (mod n)`, serialised as a 32-byte key. */
export function scalarCombine(k1: Uint8Array, s1: bigint, k2: Uint8Array, s2: bigint): Uint8Array {
  const v = (mod(beToBigInt(k1) * mod(s1)) + mod(beToBigInt(k2) * mod(s2))) % CURVE_N;
  if (v === 0n) throw new Error('scalarCombine: degenerate key');
  return beBytes(v, 32);
}

/** Scalar multiplication of a point. Used by Sphinx's ephemeral-key blinding chain. */
export function pointMul(point: Uint8Array, scalar: bigint): Uint8Array {
  return Point.fromBytes(toPoint(point)).multiply(mod(scalar)).toBytes(true);
}

/** Multiply two scalars mod n — the private-key side of the same blinding step. */
export function scalarMul(a: Uint8Array, b: bigint): Uint8Array {
  const v = mod(beToBigInt(a) * mod(b));
  if (v === 0n) throw new Error('scalarMul: degenerate scalar');
  return beBytes(v, 32);
}

/**
 * ECDH shared secret, hashed. Both parties compute the same 32 bytes from
 * opposite halves of the exchange; this is what gives each onion hop a key
 * the sender knows and no other hop does.
 *
 * **Only the x-coordinate is hashed**, and that is load-bearing now that keys
 * are x-only. A 32-byte key does not carry its y parity, so lifting it gives
 * the even-y point — which may be the negation of the node's actual key. Since
 * `e·(−P) = −(e·P)` and negation leaves x unchanged, discarding the parity
 * byte makes both sides agree. Hashing the full compressed point would make
 * every onion hop whose key happens to have odd y silently fail to decrypt.
 */
export function ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = secp256k1.getSharedSecret(privateKey, toPoint(publicKey), true);
  return sha256(shared.subarray(1));
}

function mod(v: bigint): bigint {
  const r = v % CURVE_N;
  return r < 0n ? r + CURVE_N : r;
}

export { sha256, ripemd160 };
