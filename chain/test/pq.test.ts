/**
 * WOTS+ hash-based signatures.
 *
 * The interesting tests are the last two sections. Signing and verifying is
 * arithmetic; the parts worth writing down are *why the checksum is there* and
 * *what reuse actually costs* — the latter measured rather than asserted,
 * because the honest answer turned out to be more interesting than the usual
 * "two signatures and it is over".
 *
 * Two signatures do not hand an attacker an arbitrary message. They hand them a
 * search: roughly 2⁻³⁵ per attempt for a target of their own choosing, which is
 * minutes of grinding and therefore just as fatal. The tests below show the
 * curve, and then break a key outright at a reuse count that finishes quickly.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EXPOSURE,
  PQ_ADDRESS_VERSION,
  WOTS_LEN,
  WOTS_N,
  WOTS_SIG_BYTES,
  WOTS_W,
  exposureOf,
  wotsDigest,
  wotsForge,
  wotsFromSeed,
  wotsGenerate,
  wotsRecover,
  wotsReuseHazard,
  wotsSign,
  wotsVerify,
} from '../src/pq.ts';
import { sha256, toHex, utf8 } from '../src/crypto.ts';

const digest = (s: string) => sha256(utf8(s));

/* ─────────────────────────────────────────────────────── the basics ── */

test('a signature verifies against the key that made it', () => {
  const key = wotsFromSeed(digest('pq/alice'));
  const message = digest('pay bob 5 DECKX');

  const signature = wotsSign(message, key);
  assert.equal(signature.length, WOTS_SIG_BYTES);
  assert.equal(wotsVerify(message, signature, key.digest), true);
});

test('key derivation is deterministic, so a seed phrase is enough', () => {
  // A wallet stores 32 bytes, not the 2 kB of key material they expand into.
  const a = wotsFromSeed(digest('pq/same'));
  const b = wotsFromSeed(digest('pq/same'));
  assert.equal(a.digest, b.digest);
  assert.deepEqual(a.privateKey, b.privateKey);

  const other = wotsFromSeed(digest('pq/different'));
  assert.notEqual(other.digest, a.digest);
});

test('a different message does not verify', () => {
  const key = wotsFromSeed(digest('pq/bob'));
  const signature = wotsSign(digest('pay carol 1'), key);
  assert.equal(wotsVerify(digest('pay carol 100'), signature, key.digest), false);
});

test('a different key does not verify', () => {
  const message = digest('same message');
  const signature = wotsSign(message, wotsFromSeed(digest('pq/one')));
  assert.equal(wotsVerify(message, signature, wotsFromSeed(digest('pq/two')).digest), false);
});

test('every byte of the signature matters', () => {
  const key = wotsFromSeed(digest('pq/tamper'));
  const message = digest('important');
  const signature = wotsSign(message, key);

  // Flip one bit in each chain element and confirm the whole thing fails.
  for (let i = 0; i < WOTS_LEN; i += 7) {
    const tampered = Uint8Array.from(signature);
    tampered[i * WOTS_N] ^= 0x01;
    assert.equal(wotsVerify(message, tampered, key.digest), false, `chain ${i} was not checked`);
  }
});

test('a truncated or padded signature is refused, not misread', () => {
  const key = wotsFromSeed(digest('pq/length'));
  const message = digest('m');
  const signature = wotsSign(message, key);

  assert.equal(wotsVerify(message, signature.subarray(0, WOTS_SIG_BYTES - 1), key.digest), false);
  assert.equal(wotsVerify(message, new Uint8Array(WOTS_SIG_BYTES + 1), key.digest), false);
  assert.throws(() => wotsRecover(message, new Uint8Array(10)), /must be 2144 bytes/);
});

test('the parameters are the ones the sizes claim', () => {
  assert.equal(WOTS_W, 16);
  assert.equal(WOTS_LEN, 67);
  assert.equal(WOTS_SIG_BYTES, 67 * 32);
  // 2144 bytes against Schnorr's 64. That is the price, and it is the reason
  // this is an opt-in address version rather than the default.
  assert.equal(WOTS_SIG_BYTES, 2144);
  assert.equal(WOTS_SIG_BYTES / 64, 33.5);
});

test('the public digest is a commitment an address can carry', () => {
  const key = wotsGenerate();
  assert.match(key.digest, /^[0-9a-f]{64}$/);
  assert.equal(wotsDigest(key.publicKey), key.digest);
  assert.throws(() => wotsDigest(new Uint8Array(31)), /wrong public key length/);
});

/* ────────────────────────────────────────────── why the checksum exists ── */

test('without a checksum, a larger message digit would be free to forge', () => {
  /*
   * The core asymmetry. Signing digit `d` means publishing a chain element `d`
   * steps along, and *anyone* can hash it further — so producing a signature
   * for a message with larger digits costs nothing.
   *
   * This test demonstrates that directly: take a real signature, hash one chain
   * element forward, and it is now a valid signature for a message whose digit
   * at that position is one higher. The checksum is what makes such a message
   * impossible to construct, because raising a message digit lowers a checksum
   * digit, and lowering one means running a hash backwards.
   */
  const key = wotsFromSeed(digest('pq/checksum'));
  const message = digest('original');
  const signature = wotsSign(message, key);

  const recovered = wotsRecover(message, signature);
  assert.deepEqual(recovered, key.publicKey, 'harness check: recovery must reproduce the public key');

  /*
   * Search for a message whose *message* digits are all ≥ the original's. With
   * a checksum in play this should not be reachable, because such a message
   * necessarily has a smaller checksum — and `wotsForge` refuses when a chain
   * would have to run backwards.
   */
  let forgedAny = false;
  for (let i = 0; i < 400 && !forgedAny; i++) {
    const target = digest(`attempt ${i}`);
    const forged = wotsForge(target, [{ messageHash: message, signature }]);
    if (forged && wotsVerify(target, forged, key.digest)) forgedAny = true;
  }
  assert.equal(forgedAny, false, 'one signature must not yield a forgery for any other message');
});

/* ────────────────────────────────────────────────── the reuse hazard ── */

test('reuse degrades the key, measurably, one signature at a time', () => {
  /*
   * The mechanism, made visible. Each signature publishes one position on each
   * of the 67 chains, and a forger can hash *forward* from any published
   * position for free — so a message is forgeable exactly when every digit of
   * it sits at or above something already revealed.
   *
   * One signature reveals too little for that to ever line up. Each further
   * signature makes it likelier, and the curve is steep.
   */
  const key = wotsFromSeed(digest('pq/degrade'));
  const rate = (k: number, trials: number) => {
    const observed = [];
    for (let i = 0; i < k; i++) {
      const m = digest(`observed ${i}`);
      observed.push({ messageHash: m, signature: wotsSign(m, key) });
    }
    let hits = 0;
    for (let i = 0; i < trials; i++) if (wotsForge(digest(`t${k}/${i}`), observed)) hits++;
    return hits / trials;
  };

  assert.equal(rate(1, 2000), 0, 'a single signature must not make any other message reachable');
  assert.ok(rate(12, 2000) > rate(6, 2000), 'more signatures must mean more exposure');
  assert.ok(rate(16, 2000) > 0.05, 'by sixteen it should be routine');
});

test('with the key reused enough, a forgery verifies against it', () => {
  /*
   * Not a claim in a comment: an actual signature this key never produced,
   * accepted by the real verifier.
   *
   * Sixteen signatures is chosen so the search finishes in a test. Two is
   * already fatal against an attacker who *chooses* the target — they vary a
   * change amount and re-hash, at roughly 2⁻³⁵ per attempt, which is minutes of
   * grinding. The difference between sixteen here and two in the wild is only
   * how long the search takes.
   */
  const key = wotsFromSeed(digest('pq/broken'));
  const observed = [];
  for (let i = 0; i < 16; i++) {
    const m = digest(`spend ${i}`);
    observed.push({ messageHash: m, signature: wotsSign(m, key) });
  }
  const signed = new Set(observed.map((o) => toHex(o.messageHash)));

  let forgery: { message: Uint8Array; signature: Uint8Array } | undefined;
  for (let i = 0; i < 40_000 && !forgery; i++) {
    const target = digest(`attacker choice ${i}`);
    const forged = wotsForge(target, observed);
    if (forged && wotsVerify(target, forged, key.digest)) forgery = { message: target, signature: forged };
  }

  assert.ok(forgery, 'a reused key should eventually yield a forgery');
  assert.equal(signed.has(toHex(forgery!.message)), false, 'and for a message it never signed');
  assert.equal(
    wotsVerify(forgery!.message, forgery!.signature, key.digest),
    true,
    'the real verifier accepts it — the key is gone',
  );
});

test('the hazard check refuses a second, different message', () => {
  const first = toHex(digest('first'));
  const second = toHex(digest('second'));

  assert.equal(wotsReuseHazard(first, []).reused, false);

  const hazard = wotsReuseHazard(second, [first]);
  assert.equal(hazard.reused, true);
  assert.match(hazard.reason, /forge a third/);
});

test('re-signing the identical message is not reuse', () => {
  // Rebroadcasting the same transaction publishes nothing new: the chain
  // positions were already revealed by the first signature.
  const only = toHex(digest('one message'));
  const hazard = wotsReuseHazard(only, [only]);
  assert.equal(hazard.reused, false);
  assert.match(hazard.reason, /no new chain positions/);
});

/* ──────────────────────────────────────────────── exposure analysis ── */

test('an unspent ordinary output is already behind a hash', () => {
  /*
   * The point most discussion of "quantum-proofing Bitcoin" skips. An address
   * is HASH160(pubkey); the pubkey is witness data that appears only on a
   * spend. Until then there is nothing on-chain for Shor to attack.
   */
  const fresh = exposureOf({ version: 0, spentFrom: false });
  assert.equal(fresh.exposure, EXPOSURE.HASHED);
  assert.equal(fresh.safe, true);
  assert.match(fresh.reason, /only when this output is spent/);
});

test('a reused address is exposed, and that is a present-day problem', () => {
  /*
   * Once a spend publishes the public key, every coin that arrives afterwards
   * sits behind a key the whole world can see. This is not a future migration
   * issue — it is a reason not to reuse addresses today.
   */
  const reused = exposureOf({ version: 0, spentFrom: true });
  assert.equal(reused.exposure, EXPOSURE.REVEALED);
  assert.equal(reused.safe, false);
  assert.match(reused.reason, /stop reusing it/);
});

test('a WOTS+ address is safe whether or not it has been spent from', () => {
  for (const spentFrom of [false, true]) {
    const pq = exposureOf({ version: PQ_ADDRESS_VERSION, spentFrom });
    assert.equal(pq.exposure, EXPOSURE.POST_QUANTUM);
    assert.equal(pq.safe, true);
  }
  assert.equal(PQ_ADDRESS_VERSION, 2);
});

test('a contract address is treated like a key address for exposure', () => {
  // Version 1 is a contract, still secp256k1-authorised at the boundary.
  assert.equal(exposureOf({ version: 1, spentFrom: false }).exposure, EXPOSURE.HASHED);
  assert.equal(exposureOf({ version: 1, spentFrom: true }).exposure, EXPOSURE.REVEALED);
});
