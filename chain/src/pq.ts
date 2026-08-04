/**
 * WOTS+ — hash-based one-time signatures.
 *
 * Every signature elsewhere in this chain is BIP-340 Schnorr over secp256k1,
 * whose security rests on the discrete logarithm problem. Shor's algorithm
 * solves that in polynomial time on a sufficiently large quantum computer. This
 * file is the part that does not care: WOTS+ needs nothing but a hash function.
 *
 * ── Why hashes survive and elliptic curves do not ─────────────────────────
 * Shor's algorithm attacks *structure* — the group structure of a curve, the
 * factorisation of an integer. A hash has none to attack. The best known
 * quantum attack on a preimage is Grover's, which is a square-root speedup: it
 * turns 2^256 work into 2^128. That is a real loss and it is also survivable,
 * which is why every post-quantum signature standard that is actually deployed
 * today (SLH-DSA / SPHINCS+) is built out of exactly this.
 *
 * WOTS+ is the one-time signature at the bottom of SPHINCS+. Implemented here
 * with the SHA-256 the rest of the chain already uses, so the post-quantum path
 * adds no dependency and no new primitive to get wrong.
 *
 * ── How it works, in one paragraph ────────────────────────────────────────
 * The private key is `len` random 32-byte strings. The public key is each of
 * them hashed `w-1` times. To sign, the message digest is split into base-`w`
 * digits, and chain element `i` is hashed forward `digit[i]` times — so the
 * signature is a set of *partial* chains. A verifier finishes each chain and
 * checks it lands on the public key. Signing a larger digit means releasing a
 * chain closer to its end, so a forger who wants a *larger* digit only has to
 * hash forward, which is free. That is what the checksum prevents: it moves in
 * the opposite direction, so raising any message digit lowers a checksum digit,
 * and lowering a digit requires inverting the hash.
 *
 * ── The constraint that makes this dangerous ──────────────────────────────
 * **One time.** Two signatures under one key reveal two different points on the
 * same chains, and from those an attacker can forge a third message. This is
 * not a weakening; it is a total break of that key.
 *
 * A UTXO chain suits this unusually well: an output is spent exactly once, so
 * each key signs exactly once — *provided each address is used once*. Paying
 * the same address twice creates two outputs under one key, and spending both
 * is the break. `wotsReuseHazard` exists to make that state detectable rather
 * than merely documented, and the wallet refuses to build the second spend.
 */

import { concat, sha256, taggedHash, toHex, fromHex, randomPrivateKey, type Hex } from './crypto.ts';

/** Winternitz parameter. 16 means four bits per chain, 67 chains. */
export const WOTS_W = 16;
/** Bytes of message digest signed. */
export const WOTS_N = 32;
/** Chains covering the message: ceil(256 / log2(16)) = 64. */
export const WOTS_LEN1 = 64;
/** Chains covering the checksum. */
export const WOTS_LEN2 = 3;
export const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2; // 67

/** A WOTS+ signature is `len` chain elements: 67 × 32 = 2144 bytes. */
export const WOTS_SIG_BYTES = WOTS_LEN * WOTS_N;

export interface WotsKeyPair {
  /** `len` × 32 bytes. Whoever holds this can sign — once. */
  readonly privateKey: Uint8Array;
  /** `len` × 32 bytes, each the end of a chain. */
  readonly publicKey: Uint8Array;
  /** 32-byte commitment to the public key. This is what an address holds. */
  readonly digest: Hex;
}

/* ────────────────────────────────────────────────────────────── chains ── */

/**
 * Advance one chain element `steps` times.
 *
 * Each step is domain-separated by the chain index and the position within it.
 * Without that separation the same 32 bytes appearing in two chains would
 * advance identically, and a forger could transplant a chain element from one
 * position to another.
 */
function chain(element: Uint8Array, index: number, from: number, steps: number): Uint8Array {
  let value = element;
  for (let i = 0; i < steps; i++) {
    value = taggedHash(
      'DeckxCoin/wots',
      Uint8Array.of((index >> 8) & 0xff, index & 0xff, (from + i) & 0xff),
      value,
    );
  }
  return value;
}

/** Split a digest into base-`w` digits, most significant first. */
function baseW(bytes: Uint8Array, count: number): number[] {
  const digits: number[] = [];
  for (const byte of bytes) {
    digits.push((byte >> 4) & 0x0f, byte & 0x0f);
    if (digits.length >= count) break;
  }
  return digits.slice(0, count);
}

/**
 * The checksum digits.
 *
 * Sum of `(w - 1 - digit)` over the message digits, encoded base-`w`. It runs
 * *opposite* to the message: increasing any message digit decreases the sum.
 *
 * This is the entire security argument for the scheme. Signing digit `d` means
 * revealing a chain element `d` steps along, and anyone can hash it further —
 * so forging a message with larger digits is free. The checksum makes that
 * forgery require a *smaller* checksum digit, which means an element earlier in
 * its chain, which means inverting the hash.
 */
function checksumDigits(messageDigits: readonly number[]): number[] {
  let sum = 0;
  for (const d of messageDigits) sum += WOTS_W - 1 - d;

  const digits: number[] = [];
  for (let i = WOTS_LEN2 - 1; i >= 0; i--) {
    digits[i] = sum & 0x0f;
    sum >>= 4;
  }
  return digits;
}

function digitsFor(messageHash: Uint8Array): number[] {
  if (messageHash.length !== WOTS_N) {
    throw new Error(`wots: message hash must be ${WOTS_N} bytes, got ${messageHash.length}`);
  }
  const message = baseW(messageHash, WOTS_LEN1);
  return [...message, ...checksumDigits(message)];
}

/* ───────────────────────────────────────────────────────────── the key ── */

/**
 * Derive a key pair from a 32-byte seed.
 *
 * Deterministic, so a wallet stores a seed rather than 2 kB of key material and
 * can regenerate the whole thing from its mnemonic.
 */
export function wotsFromSeed(seed: Uint8Array): WotsKeyPair {
  if (seed.length !== WOTS_N) throw new Error(`wots: seed must be ${WOTS_N} bytes`);

  const privateKey = new Uint8Array(WOTS_LEN * WOTS_N);
  const publicKey = new Uint8Array(WOTS_LEN * WOTS_N);

  for (let i = 0; i < WOTS_LEN; i++) {
    const element = taggedHash('DeckxCoin/wots-seed', Uint8Array.of((i >> 8) & 0xff, i & 0xff), seed);
    privateKey.set(element, i * WOTS_N);
    // The public element is the far end of the chain: w-1 steps from the start.
    publicKey.set(chain(element, i, 0, WOTS_W - 1), i * WOTS_N);
  }

  return { privateKey, publicKey, digest: toHex(sha256(publicKey)) };
}

export function wotsGenerate(): WotsKeyPair {
  return wotsFromSeed(randomPrivateKey());
}

/** The 32-byte commitment an address carries. */
export function wotsDigest(publicKey: Uint8Array): Hex {
  if (publicKey.length !== WOTS_LEN * WOTS_N) throw new Error('wots: wrong public key length');
  return toHex(sha256(publicKey));
}

/* ────────────────────────────────────────────────────── sign / verify ── */

/**
 * Sign a 32-byte digest. **Once.**
 *
 * There is no guard here, because a signing function cannot know whether the
 * caller has used this key before — the state that would answer that lives in
 * the wallet and in the UTXO set. See `wotsReuseHazard`.
 */
export function wotsSign(messageHash: Uint8Array, key: WotsKeyPair): Uint8Array {
  const digits = digitsFor(messageHash);
  const signature = new Uint8Array(WOTS_SIG_BYTES);

  for (let i = 0; i < WOTS_LEN; i++) {
    const element = key.privateKey.subarray(i * WOTS_N, (i + 1) * WOTS_N);
    signature.set(chain(element, i, 0, digits[i]), i * WOTS_N);
  }
  return signature;
}

/**
 * Recover the public key a signature implies, then compare digests.
 *
 * Recovery rather than re-signing: the verifier finishes each chain from where
 * the signature left it and checks the ends match. It never needs the private
 * key, and it never needs to know the digits in advance.
 */
export function wotsRecover(messageHash: Uint8Array, signature: Uint8Array): Uint8Array {
  if (signature.length !== WOTS_SIG_BYTES) {
    throw new Error(`wots: signature must be ${WOTS_SIG_BYTES} bytes, got ${signature.length}`);
  }
  const digits = digitsFor(messageHash);
  const recovered = new Uint8Array(WOTS_LEN * WOTS_N);

  for (let i = 0; i < WOTS_LEN; i++) {
    const element = signature.subarray(i * WOTS_N, (i + 1) * WOTS_N);
    recovered.set(chain(element, i, digits[i], WOTS_W - 1 - digits[i]), i * WOTS_N);
  }
  return recovered;
}

/** Does this signature open the commitment in an address? */
export function wotsVerify(messageHash: Uint8Array, signature: Uint8Array, digest: Hex): boolean {
  try {
    return wotsDigest(wotsRecover(messageHash, signature)) === digest;
  } catch {
    return false;
  }
}

/* ─────────────────────────────────────────────────────────── reuse ── */

export interface ReuseHazard {
  readonly reused: boolean;
  readonly reason: string;
}

/**
 * Would signing this second message break the key?
 *
 * ── What reuse actually costs, measured ───────────────────────────────────
 * Each signature publishes one position on each of the 67 chains. A forger can
 * hash *forward* from any published position for free, so a message is forgeable
 * exactly when every one of its digits is at or above some position already
 * revealed on that chain.
 *
 * With one signature that is essentially never. The rate for a *random* target,
 * measured in `test/pq.test.ts`:
 *
 *     signatures seen     random target forgeable
 *     ───────────────     ──────────────────────
 *     1–4                 not once in 3000
 *     6                   about 1 in 1500
 *     8                   about 1 in 330
 *     12                  about 1 in 27
 *
 * ── Why two is already fatal in practice ──────────────────────────────────
 * Those figures are for a target the attacker cannot choose. A real attacker
 * chooses: they vary a change amount by one zap, or a memo, and re-hash. Each
 * attempt is one hash. At two signatures the per-attempt odds are on the order
 * of 2⁻³⁵ — minutes of grinding on ordinary hardware for a transaction of their
 * own construction that this key appears to have authorised.
 *
 * So the rule is not "avoid many signatures". It is **one**. A wallet must
 * refuse the second spend, and the only way to refuse is to remember the first.
 * This function is what a wallet asks.
 */
export function wotsReuseHazard(digest: Hex, alreadySigned: readonly Hex[]): ReuseHazard {
  if (alreadySigned.length === 0) return { reused: false, reason: 'this key has not signed' };
  if (alreadySigned.includes(digest)) {
    // Re-broadcasting the identical signature is safe: it reveals nothing that
    // is not already public.
    return { reused: false, reason: 'the same message, already signed — no new chain positions are revealed' };
  }
  return {
    reused: true,
    reason:
      `this key has already signed ${alreadySigned.length} other message(s). ` +
      'A second signature reveals two positions on every chain and lets anyone forge a third.',
  };
}

/**
 * Demonstrate the break, for a test to assert on.
 *
 * Given two signatures under one key, produce a forgery for a third message the
 * key holder never signed. Only possible when every digit of the target is
 * reachable — that is, greater than or equal to a digit already revealed on the
 * same chain — which is exactly the condition reuse creates.
 *
 * Present so the hazard is a demonstrated fact rather than a claim in a comment.
 */
export function wotsForge(
  targetHash: Uint8Array,
  observed: ReadonlyArray<{ messageHash: Uint8Array; signature: Uint8Array }>,
): Uint8Array | undefined {
  const target = digitsFor(targetHash);
  const forged = new Uint8Array(WOTS_SIG_BYTES);

  for (let i = 0; i < WOTS_LEN; i++) {
    // The best starting point is the *largest* digit seen on this chain that
    // does not overshoot: chains only move forward.
    let best: { digit: number; element: Uint8Array } | undefined;
    for (const seen of observed) {
      const digit = digitsFor(seen.messageHash)[i];
      if (digit <= target[i] && (!best || digit > best.digit)) {
        best = { digit, element: seen.signature.subarray(i * WOTS_N, (i + 1) * WOTS_N) };
      }
    }
    if (!best) return undefined; // this chain would need to run backwards
    forged.set(chain(best.element, i, best.digit, target[i] - best.digit), i * WOTS_N);
  }
  return forged;
}

/* ──────────────────────────────────────────────── exposure analysis ── */

export const EXPOSURE = {
  /** Behind a hash. A quantum attacker sees no public key to attack. */
  HASHED: 'hashed',
  /** The public key is on-chain in a witness. Vulnerable to Shor. */
  REVEALED: 'revealed',
  /** Hash-based signature. No public-key structure to attack at all. */
  POST_QUANTUM: 'post-quantum',
} as const;

export type Exposure = (typeof EXPOSURE)[keyof typeof EXPOSURE];

/**
 * How exposed is a coin sitting at this address?
 *
 * The distinction people miss: an *unspent* output paying a normal DeckxCoin
 * address is already awkward for a quantum attacker. The address is
 * HASH160(pubkey), and the pubkey is witness data that only appears when the
 * output is spent — so there is nothing on-chain to run Shor against.
 *
 * The exposure begins at the moment of spending, and it becomes permanent if
 * the address is reused: once a spend has published the public key, every coin
 * that arrives at that address afterwards sits behind a key the whole world can
 * see. That is not a future problem to be solved by a migration; it is a
 * present-day reason not to reuse addresses.
 */
export function exposureOf(opts: {
  /** Address version: 0 key, 1 contract, 2 WOTS+. */
  readonly version: number;
  /** Has any output at this address already been spent? */
  readonly spentFrom: boolean;
}): { exposure: Exposure; safe: boolean; reason: string } {
  if (opts.version === PQ_ADDRESS_VERSION) {
    return {
      exposure: EXPOSURE.POST_QUANTUM,
      safe: true,
      reason: 'hash-based signature — no public-key structure for Shor to attack',
    };
  }
  if (opts.spentFrom) {
    return {
      exposure: EXPOSURE.REVEALED,
      safe: false,
      reason:
        'a spend from this address has published its public key. Coins sent here now ' +
        'are protected by a key an attacker can already see — move them, and stop reusing it',
    };
  }
  return {
    exposure: EXPOSURE.HASHED,
    safe: true,
    reason: 'the public key is still behind HASH160 and appears only when this output is spent',
  };
}

/** bech32m version byte for an address that commits to a WOTS+ key. */
export const PQ_ADDRESS_VERSION = 2;
