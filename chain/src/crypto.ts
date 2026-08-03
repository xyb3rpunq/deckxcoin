/**
 * DeckxCoin — cryptographic primitives.
 *
 * Bitcoin heritage: double-SHA256 for block/tx identifiers, HASH160
 * (RIPEMD160 ∘ SHA256) for address commitments, secp256k1 ECDSA for
 * authorisation. Ethereum heritage: keccak-style domain separation for
 * contract addresses and storage slots (we use SHA256 with explicit domain
 * tags instead of keccak so the whole chain needs exactly one hash family).
 *
 * Every hash here is domain-separated. Two different structures can never
 * produce the same preimage, which is the bug class that killed more than one
 * altcoin.
 */

import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import * as secp from '@noble/secp256k1';
import { bech32m, hex as hexCodec } from '@scure/base';

// @noble/secp256k1 v2 is sync-capable only once an HMAC-SHA256 is injected.
secp.etc.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]) =>
  hmac(sha256, key, secp.etc.concatBytes(...msgs));

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
  readonly publicKey: Uint8Array; // 33-byte compressed
  readonly address: string;
}

export function randomPrivateKey(): Uint8Array {
  return secp.utils.randomPrivateKey();
}

/**
 * Deterministic key derivation from a seed phrase. Used by the CLI and the
 * test-vectors so a documented genesis is byte-for-byte reproducible on any
 * machine. Not a BIP-32 wallet — DeckxCoin keys are single-purpose.
 */
export function keyFromSeed(seed: string): Uint8Array {
  let material = taggedHash('DeckxCoin/seed', utf8(seed));
  // Reject-and-rehash until the scalar is in range, exactly like BIP-32 does.
  for (let i = 0; i < 256; i++) {
    if (secp.utils.isValidPrivateKey(material)) return material;
    material = taggedHash('DeckxCoin/seed/retry', material);
  }
  throw new Error('keyFromSeed: exhausted retries');
}

export function keyPair(privateKey: Uint8Array): KeyPair {
  const publicKey = secp.getPublicKey(privateKey, true);
  return { privateKey, publicKey, address: addressFromPubkey(publicKey) };
}

export const keyPairFromSeed = (seed: string): KeyPair => keyPair(keyFromSeed(seed));

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

/** Sign a 32-byte digest. Returns 64-byte compact (r‖s) hex. */
export function sign(digest: Uint8Array, privateKey: Uint8Array): Hex {
  if (digest.length !== 32) throw new Error('sign: digest must be 32 bytes');
  return toHex(secp.sign(digest, privateKey).toCompactRawBytes());
}

export function verify(signature: Hex, digest: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return secp.verify(fromHex(signature), digest, publicKey);
  } catch {
    return false;
  }
}

/* ----------------------------------------------- adaptor points (PTLC-ready) */

/**
 * Point derived from a scalar secret — the building block for PTLCs, where a
 * payment is locked to `s·G` rather than to `SHA256(preimage)`. Volt still
 * settles with hash locks today (BOLT-compatible), but every channel already
 * carries the point so the upgrade is a flag flip, not a re-spec.
 */
export function pointFromSecret(secret: Uint8Array): Uint8Array {
  return secp.getPublicKey(secret, true);
}

export function pointsEqual(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/** Order of the secp256k1 group. Scalar arithmetic is mod this. */
export const CURVE_N: bigint = secp.CURVE.n;

/**
 * Compute `P₁·s₁ + P₂·s₂` on the curve, returning a compressed point.
 *
 * Volt's revocation keys are built from this: a public key that two parties
 * can each derive from public data, but whose *private* key requires one
 * secret from each of them. No hash construction can do that — it genuinely
 * needs the group's homomorphism.
 */
export function pointCombine(p1: Uint8Array, s1: bigint, p2: Uint8Array, s2: bigint): Uint8Array {
  const P1 = secp.ProjectivePoint.fromHex(p1);
  const P2 = secp.ProjectivePoint.fromHex(p2);
  const sum = P1.multiply(mod(s1)).add(P2.multiply(mod(s2)));
  return sum.toRawBytes(true);
}

/** The matching scalar: `k₁·s₁ + k₂·s₂ (mod n)`, serialised as a 32-byte key. */
export function scalarCombine(k1: Uint8Array, s1: bigint, k2: Uint8Array, s2: bigint): Uint8Array {
  const v = (mod(beToBigInt(k1) * mod(s1)) + mod(beToBigInt(k2) * mod(s2))) % CURVE_N;
  if (v === 0n) throw new Error('scalarCombine: degenerate key');
  return beBytes(v, 32);
}

/** Scalar multiplication of a point. Used by Sphinx's ephemeral-key blinding chain. */
export function pointMul(point: Uint8Array, scalar: bigint): Uint8Array {
  return secp.ProjectivePoint.fromHex(point).multiply(mod(scalar)).toRawBytes(true);
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
 */
export function ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return sha256(secp.getSharedSecret(privateKey, publicKey, true));
}

function mod(v: bigint): bigint {
  const r = v % CURVE_N;
  return r < 0n ? r + CURVE_N : r;
}

export { sha256, ripemd160 };
