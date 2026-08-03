/**
 * Fee estimation and replace-by-fee.
 *
 * The estimator's job is to be *honest*, not confident. A wallet that quotes a
 * number with no history behind it teaches the user to distrust it, and a
 * wallet that quotes the mean wait strands payments in the tail. Both failure
 * modes are tested here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  bucketFor,
  DEFAULT_CONFIDENCE,
  FEE_BUCKETS,
  FeeEstimator,
  judgeReplacement,
  MIN_REPLACEMENT_RELAY_RATE,
  NO_ESTIMATE,
  TARGETS,
  type ReplacementCandidate,
} from '../src/node/feerate.ts';
import type { Hex } from '../src/crypto.ts';

const id = (n: number): Hex => n.toString(16).padStart(64, '0');

/* ─────────────────────────────────────────────────────────── buckets ── */

test('fee rates land in the expected bucket', () => {
  assert.equal(FEE_BUCKETS[bucketFor(0)], 0);
  assert.equal(FEE_BUCKETS[bucketFor(1)], 1);
  assert.equal(FEE_BUCKETS[bucketFor(1.4)], 1);
  assert.equal(FEE_BUCKETS[bucketFor(1.5)], 1.5);
  assert.equal(FEE_BUCKETS[bucketFor(1000)], 512);
  assert.equal(FEE_BUCKETS[bucketFor(99999)], 1024, 'anything huge lands in the top bucket');
});

test('buckets are exponential, because fee rates are', () => {
  // The interesting distinction is 1 vs 2, not 100 vs 101. Bucket widths must
  // therefore grow, or the high end is pointlessly fine-grained.
  const lowWidth = FEE_BUCKETS[4] - FEE_BUCKETS[3];
  const highWidth = FEE_BUCKETS[FEE_BUCKETS.length - 1] - FEE_BUCKETS[FEE_BUCKETS.length - 2];
  assert.ok(highWidth > lowWidth * 100, 'bucket widths must grow with the rate');
});

/* ───────────────────────────────────────────────────────── estimating ── */

test('an estimator with no history says so, rather than guessing', () => {
  const fees = new FeeEstimator();
  const estimate = fees.estimate(6);

  assert.equal(estimate.feeRate, NO_ESTIMATE);
  assert.equal(estimate.samples, 0);
  assert.match(estimate.basis, /no confirmations observed yet/);
  // Every horizon, not just the one asked for.
  for (const e of fees.all()) assert.equal(e.feeRate, NO_ESTIMATE);
});

test('a fee rate that consistently confirms quickly is quoted', () => {
  const fees = new FeeEstimator();

  // Twenty transactions at 4 zaps/byte, every one confirming in one block.
  for (let i = 0; i < 20; i++) {
    fees.entered(id(i), 4, 100 + i);
    fees.confirmed(id(i), 101 + i);
  }

  const estimate = fees.estimate(1);
  assert.equal(estimate.feeRate, 4);
  assert.equal(estimate.confidence, 1);
  assert.equal(estimate.samples, 20);
  assert.match(estimate.basis, /20\/20 transactions/);
});

test('the estimate is a percentile, not a mean — the tail is what strands payments', () => {
  const fees = new FeeEstimator(0.85);

  /*
   * Twenty transactions at 2 zaps/byte: sixteen confirm next block, four take
   * ten blocks. The *mean* wait is under three blocks, so a mean-based
   * estimator would happily quote this rate for a two-block target — and one
   * payment in five would hang.
   */
  for (let i = 0; i < 16; i++) {
    fees.entered(id(i), 2, 100);
    fees.confirmed(id(i), 101);
  }
  for (let i = 16; i < 20; i++) {
    fees.entered(id(i), 2, 100);
    fees.confirmed(id(i), 110);
  }

  const mean = (16 * 1 + 4 * 10) / 20;
  assert.ok(mean < 3, `harness check: the mean wait is ${mean}, which looks fine`);

  // 16/20 = 80%, below the 85% threshold, so this rate is not offered.
  const twoBlocks = fees.estimate(2);
  assert.notEqual(twoBlocks.feeRate, 2, 'an 80% rate must not be quoted at 85% confidence');

  // Over a horizon that covers the tail, it is.
  const tenBlocks = fees.estimate(10);
  assert.equal(tenBlocks.feeRate, 2);
  assert.equal(tenBlocks.confidence, 1);
});

test('the cheapest rate clearing the threshold wins', () => {
  const fees = new FeeEstimator();
  let n = 0;

  // 1 zap/byte always waits; 3 zaps/byte always confirms; 8 also confirms.
  for (let i = 0; i < 10; i++, n++) {
    fees.entered(id(n), 1, 100);
    fees.confirmed(id(n), 150);
  }
  for (let i = 0; i < 10; i++, n++) {
    fees.entered(id(n), 3, 100);
    fees.confirmed(id(n), 101);
  }
  for (let i = 0; i < 10; i++, n++) {
    fees.entered(id(n), 8, 100);
    fees.confirmed(id(n), 101);
  }

  const estimate = fees.estimate(2);
  assert.equal(estimate.feeRate, 3, 'must pick the cheapest sufficient rate, not the fastest');
});

test('a bucket with too little history is skipped rather than trusted', () => {
  const fees = new FeeEstimator();

  // Two lucky confirmations at a very low rate.
  fees.entered(id(1), 0.5, 100);
  fees.confirmed(id(1), 101);
  fees.entered(id(2), 0.5, 100);
  fees.confirmed(id(2), 101);

  // Plenty at a higher rate.
  for (let i = 10; i < 30; i++) {
    fees.entered(id(i), 6, 100);
    fees.confirmed(id(i), 101);
  }

  const estimate = fees.estimate(1);
  assert.equal(estimate.feeRate, 6, 'two samples must not outvote twenty');
});

test('transactions the estimator never saw enter are not counted as instant', () => {
  const fees = new FeeEstimator();

  // A block arrives full of transactions this node never had in its mempool.
  fees.onBlock([id(1), id(2), id(3)], 500);
  assert.equal(fees.observations, 0, 'unseen transactions teach nothing');
  assert.equal(fees.estimate(1).feeRate, NO_ESTIMATE);
});

test('a dropped transaction is forgotten, not recorded as a long wait', () => {
  const fees = new FeeEstimator();
  fees.entered(id(1), 5, 100);
  assert.equal(fees.pendingCount, 1);

  fees.dropped(id(1));
  assert.equal(fees.pendingCount, 0);
  assert.equal(fees.observations, 0, 'an expiry is not a confirmation time');
});

test('every standard horizon gets an answer', () => {
  const fees = new FeeEstimator();
  for (let i = 0; i < 20; i++) {
    fees.entered(id(i), 16, 100);
    fees.confirmed(id(i), 101);
  }

  const all = fees.all();
  assert.equal(all.length, TARGETS.length);
  for (const estimate of all) {
    assert.equal(estimate.feeRate, 16, `target ${estimate.target} should be satisfied`);
  }
  assert.equal(fees.stats().observations, 20);
  assert.equal(DEFAULT_CONFIDENCE, 0.85);
});

test('a nonsensical target is refused', () => {
  const fees = new FeeEstimator();
  assert.match(fees.estimate(0).basis, /at least 1 block/);
  assert.match(fees.estimate(-3).basis, /at least 1 block/);
});

/* ────────────────────────────────────────────────── replace-by-fee ── */

const spend = (n: number): ReplacementCandidate['inputs'] => [{ txid: id(n), vout: 0 }];

test('a replacement must actually conflict with something', () => {
  const verdict = judgeReplacement(
    { txid: id(99), fee: 10_000n, size: 200, inputs: spend(1) },
    [],
  );
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /nothing to replace/);
});

test('a replacement paying less is refused', () => {
  const original: ReplacementCandidate = { txid: id(1), fee: 5_000n, size: 200, inputs: spend(1) };
  const cheaper: ReplacementCandidate = { txid: id(2), fee: 4_000n, size: 200, inputs: spend(1) };

  const verdict = judgeReplacement(cheaper, [original]);
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /must exceed the 5000 it displaces/);
});

test('a bigger transaction cannot buy its way in with a token increase', () => {
  /*
   * The rule that stops mempool churn being free. Without a rate check, an
   * attacker replaces a 200-byte transaction with a 100,000-byte one paying
   * one zap more, and every node on the network relays 100 kB for nothing.
   */
  const original: ReplacementCandidate = { txid: id(1), fee: 5_000n, size: 200, inputs: spend(1) };
  const bloated: ReplacementCandidate = { txid: id(2), fee: 5_001n, size: 100_000, inputs: spend(1) };

  const verdict = judgeReplacement(bloated, [original]);
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /does not exceed/);
});

test('the fee increase must cover the replacement’s own relay cost', () => {
  const original: ReplacementCandidate = { txid: id(1), fee: 1_000n, size: 100, inputs: spend(1) };
  // Higher rate and higher absolute fee, but the increase is tiny relative to
  // the bytes it asks the network to carry.
  const stingy: ReplacementCandidate = { txid: id(2), fee: 1_050n, size: 100, inputs: spend(1) };

  const verdict = judgeReplacement(stingy, [original]);
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /does not cover 100 zaps of relay/);
  assert.equal(MIN_REPLACEMENT_RELAY_RATE, 1n);
});

test('RBF: a properly bumped transaction replaces the original', () => {
  const original: ReplacementCandidate = { txid: id(1), fee: 1_000n, size: 200, inputs: spend(1) };
  const bumped: ReplacementCandidate = { txid: id(2), fee: 4_000n, size: 200, inputs: spend(1) };

  const verdict = judgeReplacement(bumped, [original]);
  assert.equal(verdict.allowed, true, verdict.reason);
  assert.deepEqual(verdict.replaces, [id(1)]);
  assert.equal(verdict.feeIncrease, 3_000n);
});

test('a replacement must outbid every transaction it displaces, together', () => {
  // Two pooled transactions share inputs with the replacement. Beating the
  // larger one is not enough — the total is what the network gives up.
  const first: ReplacementCandidate = { txid: id(1), fee: 3_000n, size: 200, inputs: spend(1) };
  const second: ReplacementCandidate = { txid: id(2), fee: 3_000n, size: 200, inputs: spend(2) };

  const notEnough: ReplacementCandidate = {
    txid: id(3),
    fee: 4_000n,
    size: 200,
    inputs: [...spend(1), ...spend(2)],
  };
  assert.equal(judgeReplacement(notEnough, [first, second]).allowed, false);

  const enough: ReplacementCandidate = {
    txid: id(4),
    fee: 12_000n,
    size: 200,
    inputs: [...spend(1), ...spend(2)],
  };
  const verdict = judgeReplacement(enough, [first, second]);
  assert.equal(verdict.allowed, true, verdict.reason);
  assert.equal(verdict.replaces.length, 2);
  assert.equal(verdict.feeIncrease, 6_000n);
});

test('a zero-size transaction cannot game the rate comparison', () => {
  const original: ReplacementCandidate = { txid: id(1), fee: 1_000n, size: 0, inputs: spend(1) };
  const candidate: ReplacementCandidate = { txid: id(2), fee: 2_000n, size: 0, inputs: spend(1) };

  // Both rates compute as 0, so the rate check refuses rather than dividing by
  // zero or letting it through.
  const verdict = judgeReplacement(candidate, [original]);
  assert.equal(verdict.allowed, false);
});
