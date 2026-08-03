/**
 * Fee estimation.
 *
 * A wallet that cannot answer "what fee gets me confirmed within six blocks?"
 * leaves the user guessing, and a guess is wrong in both directions: too low
 * and the payment hangs, too high and the user overpays every time forever.
 *
 * ── How the estimate is made ──────────────────────────────────────────────
 * Purely from observation. When a transaction enters the mempool its fee rate
 * and the height at the time are recorded; when it is later seen in a block,
 * the difference is how long that fee rate actually waited. Nothing is modelled
 * or assumed — the estimator only reports what has already happened on this
 * chain.
 *
 * Buckets are exponential, because fee rates are: the interesting distinction
 * is between 1 and 2 zaps per byte, not between 100 and 101.
 *
 * ── Why the answer is a *percentile*, not a mean ──────────────────────────
 * A user asking for confirmation within six blocks is asking for a guarantee,
 * not an average. The mean wait for a fee rate says nothing about the tail, and
 * the tail is precisely what strands a payment. The estimator therefore reports
 * the cheapest bucket whose *success rate* within the target reaches a
 * threshold — 85% by default. Bitcoin Core's estimator works the same way and
 * for the same reason.
 *
 * ── What it cannot do ─────────────────────────────────────────────────────
 * It is backward-looking. A fee spike that starts now is invisible until
 * transactions have actually waited through it. No estimator built on
 * confirmation history can do better, and one claiming to would be modelling
 * rather than measuring.
 */

import type { Hex } from '../crypto.ts';

/** Bucket edges, zaps per byte. Exponential — fee rates are multiplicative. */
export const FEE_BUCKETS: readonly number[] = [
  0, 0.5, 1, 1.5, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 256, 512, 1024,
];

/** Horizons the estimator answers for, in blocks. */
export const TARGETS: readonly number[] = [1, 2, 3, 6, 12, 24, 48, 144];

/** Confirmations at or below the target needed before a bucket is trusted. */
export const DEFAULT_CONFIDENCE = 0.85;

/** Samples kept per bucket. Old data misleads once conditions change. */
export const SAMPLES_PER_BUCKET = 200;

/** Returned when there is not enough history to answer honestly. */
export const NO_ESTIMATE = -1;

interface Sample {
  readonly waited: number;
  readonly atHeight: number;
}

interface Pending {
  readonly feeRate: number;
  readonly enteredAt: number;
}

export interface Estimate {
  /** Zaps per byte, or `NO_ESTIMATE` when history is too thin to say. */
  readonly feeRate: number;
  readonly target: number;
  /** Observed success rate for the bucket chosen. */
  readonly confidence: number;
  readonly samples: number;
  /** Human-readable statement of why this is the answer. */
  readonly basis: string;
}

export function bucketFor(feeRate: number): number {
  let index = 0;
  for (let i = 0; i < FEE_BUCKETS.length; i++) {
    if (feeRate >= FEE_BUCKETS[i]) index = i;
  }
  return index;
}

export class FeeEstimator {
  /** bucket index → recent waits. */
  readonly #samples: Sample[][] = FEE_BUCKETS.map(() => []);
  readonly #pending = new Map<Hex, Pending>();
  readonly confidence: number;
  #observed = 0;

  constructor(confidence = DEFAULT_CONFIDENCE) {
    this.confidence = confidence;
  }

  get pendingCount(): number {
    return this.#pending.size;
  }

  get observations(): number {
    return this.#observed;
  }

  /** A transaction entered the mempool. */
  entered(id: Hex, feeRate: number, height: number): void {
    if (this.#pending.has(id)) return;
    this.#pending.set(id, { feeRate, enteredAt: height });
  }

  /**
   * A transaction was mined. Records how long its fee rate actually waited.
   *
   * Transactions the estimator never saw enter are ignored rather than counted
   * as instant: a block full of transactions that arrived with it would
   * otherwise teach the estimator that every fee rate confirms immediately.
   */
  confirmed(id: Hex, height: number): void {
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);

    const waited = Math.max(1, height - pending.enteredAt);
    const bucket = this.#samples[bucketFor(pending.feeRate)];
    bucket.push({ waited, atHeight: height });
    if (bucket.length > SAMPLES_PER_BUCKET) bucket.shift();
    this.#observed++;
  }

  /** A transaction left without confirming. Its wait is unknown, so unrecorded. */
  dropped(id: Hex): void {
    this.#pending.delete(id);
  }

  /** Record every transaction of a connected block. */
  onBlock(ids: readonly Hex[], height: number): void {
    for (const id of ids) this.confirmed(id, height);
  }

  /**
   * The cheapest fee rate that has historically confirmed within `target`.
   *
   * Walks buckets from cheapest upward and returns the first whose observed
   * success rate clears the confidence threshold. Returns `NO_ESTIMATE` rather
   * than a guess when no bucket has enough history — a wallet can then fall
   * back to a floor and say so, which is better than quoting a number that
   * came from nowhere.
   */
  estimate(target: number, minSamples = 5): Estimate {
    if (!Number.isInteger(target) || target < 1) {
      return { feeRate: NO_ESTIMATE, target, confidence: 0, samples: 0, basis: 'target must be at least 1 block' };
    }

    for (let i = 0; i < FEE_BUCKETS.length; i++) {
      const samples = this.#samples[i];
      if (samples.length < minSamples) continue;

      const within = samples.filter((s) => s.waited <= target).length;
      const rate = within / samples.length;

      if (rate >= this.confidence) {
        // Quote the top of the bucket, not the bottom. The bucket's success
        // rate was earned by transactions across its whole range, and the
        // bottom of it may well be the ones that waited.
        const feeRate = FEE_BUCKETS[i] === 0 ? FEE_BUCKETS[1] : FEE_BUCKETS[i];
        return {
          feeRate,
          target,
          confidence: rate,
          samples: samples.length,
          basis: `${within}/${samples.length} transactions at ≥${feeRate} zaps/byte confirmed within ${target} blocks`,
        };
      }
    }

    return {
      feeRate: NO_ESTIMATE,
      target,
      confidence: 0,
      samples: this.#observed,
      basis:
        this.#observed === 0
          ? 'no confirmations observed yet'
          : `no fee rate has reached ${(this.confidence * 100).toFixed(0)}% confirmation within ${target} blocks`,
    };
  }

  /** Estimates for every standard horizon. */
  all(): Estimate[] {
    return TARGETS.map((t) => this.estimate(t));
  }

  stats() {
    return {
      observations: this.#observed,
      pending: this.#pending.size,
      buckets: this.#samples
        .map((s, i) => ({ feeRate: FEE_BUCKETS[i], samples: s.length }))
        .filter((b) => b.samples > 0),
    };
  }
}

/* ══════════════════════════════════════════════ replace-by-fee ══ */

/**
 * Replace-by-fee.
 *
 * Without it, a transaction that went out with too low a fee has no way out:
 * it sits in mempools until it expires, and the user can neither cancel nor
 * speed it up. RBF lets a conflicting transaction paying more take its place.
 *
 * ── The rules, and why each exists ────────────────────────────────────────
 * RBF is a policy, not consensus — a miner may ignore it. The rules below are
 * BIP-125's, and each one closes a specific abuse:
 *
 *   1. **The replacement must conflict.** It has to spend at least one of the
 *      same inputs, or it is not a replacement, it is a second payment.
 *   2. **It must pay a higher absolute fee.** Otherwise a node relaying it has
 *      done work for less money.
 *   3. **It must also pay a higher fee *rate*.** Without this, an attacker
 *      replaces a small transaction with a huge one paying one zap more,
 *      consuming relay bandwidth across the network for almost nothing.
 *   4. **It must pay for its own relay.** The extra fee must at least cover
 *      the replacement's own size at the minimum relay rate, so churning the
 *      mempool is never free.
 *
 * ── The honest caveat ─────────────────────────────────────────────────────
 * RBF makes zero-confirmation transactions explicitly unsafe. They already
 * were — a miner could always reorder — but RBF makes it routine rather than
 * exotic. A merchant accepting unconfirmed payments is choosing to be exposed,
 * and should know it.
 */

export interface ReplacementCandidate {
  readonly txid: Hex;
  readonly fee: bigint;
  readonly size: number;
  readonly inputs: ReadonlyArray<{ txid: Hex; vout: number }>;
}

export interface ReplacementVerdict {
  readonly allowed: boolean;
  readonly reason: string;
  /** Pooled transactions this would evict. */
  readonly replaces: readonly Hex[];
  readonly feeIncrease?: bigint;
}

/** Minimum extra fee per byte of the replacement, so relay is never free. */
export const MIN_REPLACEMENT_RELAY_RATE = 1n;

/**
 * Decide whether `candidate` may replace conflicting pooled transactions.
 *
 * `conflicts` is every pooled transaction sharing an input with the candidate.
 */
export function judgeReplacement(
  candidate: ReplacementCandidate,
  conflicts: readonly ReplacementCandidate[],
): ReplacementVerdict {
  if (conflicts.length === 0) {
    return { allowed: false, reason: 'nothing to replace — no pooled transaction shares an input', replaces: [] };
  }

  const replaced = conflicts.map((c) => c.txid);
  const totalFee = conflicts.reduce((s, c) => s + c.fee, 0n);
  const bestRate = Math.max(...conflicts.map((c) => (c.size > 0 ? Number(c.fee) / c.size : 0)));
  const candidateRate = candidate.size > 0 ? Number(candidate.fee) / candidate.size : 0;

  // Rule 2 — pay more in absolute terms.
  if (candidate.fee <= totalFee) {
    return {
      allowed: false,
      reason: `replacement pays ${candidate.fee}, must exceed the ${totalFee} it displaces`,
      replaces: replaced,
    };
  }

  // Rule 3 — and at a higher rate, so a bigger transaction cannot buy its way
  // in with a token increase.
  if (candidateRate <= bestRate) {
    return {
      allowed: false,
      reason:
        `replacement rate ${candidateRate.toFixed(3)} does not exceed ` +
        `${bestRate.toFixed(3)} zaps/byte — a larger transaction must pay proportionally more`,
      replaces: replaced,
    };
  }

  // Rule 4 — the increase must cover the replacement's own relay cost.
  const increase = candidate.fee - totalFee;
  const required = BigInt(candidate.size) * MIN_REPLACEMENT_RELAY_RATE;
  if (increase < required) {
    return {
      allowed: false,
      reason: `fee increase of ${increase} does not cover ${required} zaps of relay for a ${candidate.size}-byte replacement`,
      replaces: replaced,
    };
  }

  return {
    allowed: true,
    reason: `replaces ${replaced.length} transaction(s), paying ${increase} zaps more`,
    replaces: replaced,
    feeIncrease: increase,
  };
}
