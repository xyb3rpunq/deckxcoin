/**
 * Adaptor signatures, and the point time-locked contracts built on them.
 *
 * An adaptor signature is a signature with a hole in it: invalid as it stands,
 * completable by exactly one secret scalar, and — the half that makes routing
 * work — revealing that scalar to anyone who sees the completed version.
 *
 * Two things are worth testing hard here. The first is the parity grind: a
 * BIP-340 verifier reconstructs the nonce point as the even-Y one, and
 * `R₀ + T` lands wherever it lands, so an implementation that ignores this
 * works for half of all keys. The second is the privacy claim, which is the
 * entire reason to prefer points over hashes.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  adaptorComplete,
  adaptorExtract,
  adaptorSign,
  adaptorVerify,
  blindPoint,
  blindScalar,
  newAdaptorSecret,
  opensPoint,
  pointForSecret,
  unblindScalar,
} from '../src/volt/adaptor.ts';
import { keyPairFromSeed, sha256, toHex, utf8, verify } from '../src/crypto.ts';
import { checkTx, signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { pickUtxo, rig } from './helpers.ts';

const digest = (s: string) => sha256(utf8(s));

/* ─────────────────────────────────────────────────────── round trip ── */

test('an adaptor completes into a signature the ordinary verifier accepts', () => {
  const key = keyPairFromSeed('adaptor/alice');
  const message = digest('pay bob 5 DECKX');
  const secret = newAdaptorSecret('adaptor/t1');

  const adaptor = adaptorSign(message, key, secret.point);
  assert.equal(adaptorVerify(message, adaptor, key.publicKey), true);

  const signature = adaptorComplete(adaptor, secret.scalar);
  // Indistinguishable on-chain from any other BIP-340 signature: nothing about
  // it says a point lock was involved.
  assert.equal(verify(signature, message, key.publicKey), true);
  assert.equal(signature.length, 128, '64 bytes, hex');
});

test('the secret comes back out of the completed signature', () => {
  const key = keyPairFromSeed('adaptor/bob');
  const message = digest('pay carol');
  const secret = newAdaptorSecret('adaptor/t2');

  const adaptor = adaptorSign(message, key, secret.point);
  const signature = adaptorComplete(adaptor, secret.scalar);

  assert.equal(adaptorExtract(signature, adaptor), secret.scalar);
});

test('the parity grind holds across many keys and messages', () => {
  /*
   * The bug this catches: BIP-340 carries `R` as an x-coordinate and the
   * verifier reconstructs the even-Y point. `R = R₀ + T` has whatever parity it
   * has, and there is no algebraic fix — negating the nonce gives `−R₀ + T`,
   * a different point. An implementation that ignores this passes its first
   * test and fails on roughly half of all inputs.
   *
   * Sixty independent (key, message, secret) triples is enough that an
   * unhandled parity would fail with probability 1 − 2⁻⁶⁰.
   */
  for (let i = 0; i < 60; i++) {
    const key = keyPairFromSeed(`adaptor/parity/${i}`);
    const message = digest(`message ${i}`);
    const secret = newAdaptorSecret(`adaptor/parity/secret/${i}`);

    const adaptor = adaptorSign(message, key, secret.point);
    assert.equal(adaptorVerify(message, adaptor, key.publicKey), true, `adaptor ${i} did not verify`);

    const signature = adaptorComplete(adaptor, secret.scalar);
    assert.equal(verify(signature, message, key.publicKey), true, `completion ${i} did not verify`);
    assert.equal(adaptorExtract(signature, adaptor), secret.scalar, `extraction ${i} was wrong`);
  }
});

/* ────────────────────────────────────────────────── what it refuses ── */

test('an adaptor signature is not itself a signature', () => {
  // The whole point: handing it over commits the signer to an offer without
  // handing over anything spendable.
  const key = keyPairFromSeed('adaptor/notyet');
  const message = digest('not yet');
  const secret = newAdaptorSecret('adaptor/t3');
  const adaptor = adaptorSign(message, key, secret.point);

  // The adaptor's own scalar, paired with the adapted nonce, must not verify.
  const forged = adaptor.nonce.slice(2) + adaptor.scalar;
  assert.equal(verify(forged, message, key.publicKey), false);
});

test('the wrong secret cannot complete it', () => {
  const key = keyPairFromSeed('adaptor/wrong');
  const message = digest('m');
  const secret = newAdaptorSecret('adaptor/right');
  const other = newAdaptorSecret('adaptor/wrong-one');

  const adaptor = adaptorSign(message, key, secret.point);
  assert.throws(() => adaptorComplete(adaptor, other.scalar), /does not open that point/);
});

test('a signature from elsewhere does not yield a secret', () => {
  // Extraction must fail loudly rather than return 32 bytes that open nothing.
  const key = keyPairFromSeed('adaptor/elsewhere');
  const message = digest('m');
  const secret = newAdaptorSecret('adaptor/t4');
  const adaptor = adaptorSign(message, key, secret.point);

  const unrelated = adaptorComplete(
    adaptorSign(message, key, newAdaptorSecret('adaptor/other').point),
    newAdaptorSecret('adaptor/other').scalar,
  );
  assert.throws(() => adaptorExtract(unrelated, adaptor), /did not complete this adaptor/);
});

test('an adaptor for one message does not verify against another', () => {
  const key = keyPairFromSeed('adaptor/msg');
  const secret = newAdaptorSecret('adaptor/t5');
  const adaptor = adaptorSign(digest('pay 1'), key, secret.point);

  assert.equal(adaptorVerify(digest('pay 100'), adaptor, key.publicKey), false);
});

test('an adaptor from one key does not verify against another', () => {
  const message = digest('m');
  const secret = newAdaptorSecret('adaptor/t6');
  const adaptor = adaptorSign(message, keyPairFromSeed('adaptor/signer'), secret.point);

  assert.equal(adaptorVerify(message, adaptor, keyPairFromSeed('adaptor/stranger').publicKey), false);
});

test('a tampered adaptor scalar is refused', () => {
  const key = keyPairFromSeed('adaptor/tamper');
  const message = digest('m');
  const secret = newAdaptorSecret('adaptor/t7');
  const adaptor = adaptorSign(message, key, secret.point);

  const bumped = {
    ...adaptor,
    scalar: adaptor.scalar.slice(0, -1) + (adaptor.scalar.endsWith('0') ? '1' : '0'),
  };
  assert.equal(adaptorVerify(message, bumped, key.publicKey), false);
});

/* ────────────────────────────────────────────────────────── blinding ── */

test('blinding gives every hop a different point for the same payment', () => {
  /*
   * The reason to prefer points over hashes at all.
   *
   * An HTLC locks every hop to SHA256(preimage) — the *same* value at every
   * hop. Two nodes anywhere on a route can compare what they were asked to
   * forward, see identical hashes, and know they are on the same payment.
   * That is the strongest deanonymisation primitive Lightning hands out, and
   * it is handed out by construction.
   */
  const secret = newAdaptorSecret('adaptor/route');
  const hop1 = newAdaptorSecret('adaptor/blind/1').scalar;
  const hop2 = newAdaptorSecret('adaptor/blind/2').scalar;

  const point1 = blindPoint(secret.point, hop1);
  const point2 = blindPoint(secret.point, hop2);

  assert.notEqual(point1, point2, 'two hops must not see the same point');
  assert.notEqual(point1, secret.point);
  // Relating them means solving a discrete log; all a hop can see is a point.
  assert.match(point1, /^0[23][0-9a-f]{64}$/);
});

test('a blinded point is opened by the correspondingly blinded scalar', () => {
  const secret = newAdaptorSecret('adaptor/unblind');
  const blinding = newAdaptorSecret('adaptor/r').scalar;

  const blinded = blindPoint(secret.point, blinding);
  const blindedScalar = blindScalar(secret.scalar, blinding);

  assert.equal(opensPoint(blindedScalar, blinded), true);
  // And the sender, knowing the blinding, recovers the original.
  assert.equal(unblindScalar(blindedScalar, blinding), secret.scalar);
});

test('an adaptor over a blinded point completes with the blinded scalar', () => {
  const key = keyPairFromSeed('adaptor/blindsign');
  const message = digest('hop payment');
  const secret = newAdaptorSecret('adaptor/base');
  const blinding = newAdaptorSecret('adaptor/blinding').scalar;

  const blinded = blindPoint(secret.point, blinding);
  const adaptor = adaptorSign(message, key, blinded);
  assert.equal(adaptorVerify(message, adaptor, key.publicKey), true);

  const signature = adaptorComplete(adaptor, blindScalar(secret.scalar, blinding));
  assert.equal(verify(signature, message, key.publicKey), true);
});

/* ──────────────────────────────────────────────── the route cascade ── */

test('THE CASCADE: the secret walks backwards along a route, hop by hop', () => {
  /*
   * The mechanism that makes a routed PTLC payment work, end to end.
   *
   * Carol picks `t` and puts `T` in her invoice. Alice, who is paying, chooses
   * a blinding scalar per hop and gives each node an adaptor signature over a
   * *different* point. When Carol completes hers to take the money, she
   * publishes a signature from which Bob extracts his blinded scalar — which is
   * exactly what he needs to complete the offer Alice made him.
   *
   * Nothing shared travels the route. Each hop learns one scalar that opens one
   * point, and neither is any use to anyone else.
   */
  const alice = keyPairFromSeed('cascade/alice');
  const bob = keyPairFromSeed('cascade/bob');

  const t = newAdaptorSecret('cascade/carol-secret');   // Carol's, from the invoice
  const rBob = newAdaptorSecret('cascade/blind-bob').scalar;   // Alice's blinding for hop 1

  // Hop 1 — Alice offers Bob a signature locked to a blinded point.
  const pointForBob = blindPoint(t.point, rBob);
  const aliceToBob = adaptorSign(digest('alice→bob htlc'), alice, pointForBob);
  assert.equal(adaptorVerify(digest('alice→bob htlc'), aliceToBob, alice.publicKey), true);

  // Hop 2 — Bob offers Carol one locked to the invoice point itself.
  const bobToCarol = adaptorSign(digest('bob→carol htlc'), bob, t.point);
  assert.equal(adaptorVerify(digest('bob→carol htlc'), bobToCarol, bob.publicKey), true);

  assert.notEqual(pointForBob, t.point, 'the two hops must be locked to different points');

  // Carol takes the money, which publishes `t` to whoever was watching.
  const carolClaim = adaptorComplete(bobToCarol, t.scalar);
  assert.equal(verify(carolClaim, digest('bob→carol htlc'), bob.publicKey), true);

  const learned = adaptorExtract(carolClaim, bobToCarol);
  assert.equal(learned, t.scalar, 'Bob learns the invoice secret from Carol claiming');

  // Bob now completes Alice's offer — but his lock was blinded, so he needs
  // the blinded scalar, which he can compute because he has `t`.
  const bobClaim = adaptorComplete(aliceToBob, blindScalar(learned, rBob));
  assert.equal(verify(bobClaim, digest('alice→bob htlc'), alice.publicKey), true);

  // And Alice, seeing Bob claim, recovers the blinded scalar and unblinds it
  // to the invoice secret — her proof of payment.
  const aliceLearned = adaptorExtract(bobClaim, aliceToBob);
  assert.equal(unblindScalar(aliceLearned, rBob), t.scalar, 'Alice ends up with the receipt');
});

test('a hop cannot use what it learned on someone else’s hop', () => {
  /*
   * The privacy claim, stated as a failure. Bob learns the scalar that opens
   * *his* point. Applied to the neighbouring hop's point it opens nothing,
   * which is what stops two hops on one route from recognising each other.
   */
  const t = newAdaptorSecret('isolate/secret');
  const r1 = newAdaptorSecret('isolate/r1').scalar;
  const r2 = newAdaptorSecret('isolate/r2').scalar;

  const point1 = blindPoint(t.point, r1);
  const point2 = blindPoint(t.point, r2);

  const scalar1 = blindScalar(t.scalar, r1);
  assert.equal(opensPoint(scalar1, point1), true);
  assert.equal(opensPoint(scalar1, point2), false, 'one hop’s scalar must not open another’s point');
});

/* ─────────────────────────────────────────────────────── boundaries ── */

test('a degenerate secret is refused rather than producing a broken signature', () => {
  const key = keyPairFromSeed('adaptor/zero');
  const message = digest('m');
  const secret = newAdaptorSecret('adaptor/t8');
  const adaptor = adaptorSign(message, key, secret.point);

  assert.throws(() => adaptorComplete(adaptor, '0'.repeat(64)), /out of range/);
  assert.throws(
    () => adaptorComplete(adaptor, 'f'.repeat(64)),
    /out of range|does not open that point/,
  );
});

test('a message that is not a 32-byte digest is refused', () => {
  const key = keyPairFromSeed('adaptor/len');
  const secret = newAdaptorSecret('adaptor/t9');
  assert.throws(() => adaptorSign(new Uint8Array(31), key, secret.point), /32-byte digest/);
  assert.equal(adaptorVerify(new Uint8Array(31), adaptorSign(digest('m'), key, secret.point), key.publicKey), false);
});

test('the point of a secret is the secret’s public key', () => {
  const secret = newAdaptorSecret('adaptor/point');
  assert.equal(pointForSecret(secret.scalar), secret.point);
  assert.equal(opensPoint(secret.scalar, secret.point), true);
});

/* ═══════════════════════════════════════════════ on-chain PTLC outputs ══ */

test('a PTLC output is swept by revealing the scalar', () => {
  /*
   * The on-chain half. A `ptlc` output is the hash lock's successor: identical
   * in shape, with "reveal x where SHA256(x) = hash" replaced by "reveal t
   * where t·G = point".
   */
  const { chain, miner } = rig('ptlc/miner');
  const payee = keyPairFromSeed('ptlc/payee');
  const refund = keyPairFromSeed('ptlc/refund');
  const secret = newAdaptorSecret('ptlc/onchain');

  const coin = pickUtxo(chain, miner.address);
  const locked = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        {
          value: ZAPS_PER_DECKX.toString(),
          address: payee.address,
          script: { type: 'ptlc', point: secret.point, timeout: chain.height + 50, refundKey: toHex(refund.publicKey) },
        },
        { value: (coin.value - ZAPS_PER_DECKX - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );
  let mined = chain.mineBlock([locked], miner.address, { time: chain.tip.header.time + 600 });
  assert.equal(mined.result.ok, true, mined.result.error);

  const prev = { value: ZAPS_PER_DECKX, address: payee.address, script: locked.outputs[0].script };
  const sweep = signTx(
    {
      ...transferTx({
        inputs: [{ txid: txid(locked), vout: 0 }],
        outputs: [{ value: (ZAPS_PER_DECKX - 1000n).toString(), address: payee.address }],
      }),
      inputs: [
        {
          txid: txid(locked), vout: 0, pubkey: '', signature: '',
          sequence: 0xffffffff,
          scalar: secret.scalar,
        },
      ],
    },
    payee,
    [prev],
  );

  const verdict = checkTx(sweep, [prev]);
  assert.equal(verdict.ok, true, verdict.error);

  mined = chain.mineBlock([sweep], miner.address, { time: chain.tip.header.time + 600 });
  assert.equal(mined.result.ok, true, mined.result.error);
  assert.equal(chain.state.balanceOf(payee.address), ZAPS_PER_DECKX - 1000n);
});

test('a wrong scalar is refused, not quietly treated as a refund', () => {
  const { chain, miner } = rig('ptlc/wrong');
  const payee = keyPairFromSeed('ptlc/payee2');
  const refund = keyPairFromSeed('ptlc/refund2');
  const secret = newAdaptorSecret('ptlc/real');
  const wrong = newAdaptorSecret('ptlc/fake');

  const coin = pickUtxo(chain, miner.address);
  const prev = {
    value: ZAPS_PER_DECKX,
    address: payee.address,
    script: { type: 'ptlc' as const, point: secret.point, timeout: chain.height + 50, refundKey: toHex(refund.publicKey) },
  };
  const sweep = signTx(
    {
      ...transferTx({
        inputs: [{ txid: coin.txid, vout: 0 }],
        outputs: [{ value: (ZAPS_PER_DECKX - 1000n).toString(), address: payee.address }],
      }),
      inputs: [{ txid: coin.txid, vout: 0, pubkey: '', signature: '', sequence: 0xffffffff, scalar: wrong.scalar }],
    },
    payee,
    [prev],
  );

  const verdict = checkTx(sweep, [prev]);
  assert.equal(verdict.ok, false);
  assert.match(verdict.error!, /does not open the committed point/);
});

test('the timeout branch needs the refund key and the locktime', () => {
  const { chain, miner } = rig('ptlc/timeout');
  const payee = keyPairFromSeed('ptlc/payee3');
  const refund = keyPairFromSeed('ptlc/refund3');
  const secret = newAdaptorSecret('ptlc/timeout-secret');
  const timeout = 500;

  const coin = pickUtxo(chain, miner.address);
  const prev = {
    value: ZAPS_PER_DECKX,
    address: payee.address,
    script: { type: 'ptlc' as const, point: secret.point, timeout, refundKey: toHex(refund.publicKey) },
  };

  const build = (key: typeof refund, lockTime: number) =>
    signTx(
      {
        ...transferTx({
          inputs: [{ txid: coin.txid, vout: 0 }],
          outputs: [{ value: (ZAPS_PER_DECKX - 1000n).toString(), address: key.address }],
        }),
        lockTime,
        inputs: [{ txid: coin.txid, vout: 0, pubkey: '', signature: '', sequence: 0xfffffffe }],
      },
      key,
      [prev],
    );

  // Too early.
  assert.match(checkTx(build(refund, timeout - 1), [prev]).error!, /lockTime >= 500/);
  // Wrong key, right time.
  assert.match(checkTx(build(payee, timeout), [prev]).error!, /requires the refund key/);
  // Right key, right time.
  assert.equal(checkTx(build(refund, timeout), [prev]).ok, true);
});
