/**
 * A testnet faucet.
 *
 * A testnet nobody can get coins on is a testnet nobody uses. This is the
 * dispenser: it holds a mined balance, and gives a small fixed amount to
 * anyone who asks, subject to limits.
 *
 * ── Why the limits are the whole design ───────────────────────────────────
 * A faucet is an unauthenticated endpoint that gives away money. Every faucet
 * without limits is drained within the hour by one script, every time, and the
 * operator learns this by discovering an empty wallet. So the interesting part
 * of a faucet is not the sending — the wallet already does that — it is the
 * refusing.
 *
 * Four limits, each closing a hole the previous one leaves open:
 *
 *   1. **Per address.** The obvious one, and the weakest: addresses are free.
 *      It stops honest double-clicks, nothing more.
 *   2. **Per IP.** Catches the script generating a fresh address per request.
 *      Bypassable with proxies, but it raises the cost from zero.
 *   3. **A rolling daily cap.** Catches the proxy pool. Rolling, not calendar:
 *      a midnight reset just teaches everyone to hammer at midnight.
 *   4. **A reserve.** The faucet refuses before the balance reaches zero, so a
 *      drained faucet is a faucet that says "empty" rather than one that
 *      throws errors at everybody and needs an operator to notice.
 *
 * ── Two bugs this file exists to not have ─────────────────────────────────
 * **Concurrent sends double-spend each other.** Two requests arriving together
 * both read the same UTXO set, both select the same coin, and the second
 * transaction is rejected as a conflict — or worse, both are relayed and the
 * faucet's own balance depends on which one a miner picks. Sends are therefore
 * serialised through a promise chain: one in flight at a time, state re-read
 * for each.
 *
 * **Check-then-send.** If the grant is recorded after the send, two requests
 * that pass the check together both get paid. The grant is recorded *before*
 * the send and rolled back if the send fails, which errs toward refusing a
 * legitimate request rather than paying twice.
 *
 * ── What a faucet cannot do ───────────────────────────────────────────────
 * It cannot tell people apart. Every limit here is a cost imposed on abuse,
 * not a prevention of it, and a determined drainer with a proxy pool will
 * still empty a faucet given a low enough per-request cost. The answer to that
 * is a small `amount` and a refill process, not cleverer heuristics.
 */

import { isValidAddress, type Hex } from '../crypto.ts';
import { formatDeckx, txid, type Transaction } from '../tx.ts';
import type { Wallet } from '../wallet/wallet.ts';
import type { WorldState } from '../state.ts';

/* ────────────────────────────────────────────────────────────── policy ── */

export interface FaucetPolicy {
  /** Zaps handed out per grant. */
  readonly amount: bigint;
  /** Minimum gap between grants to the same address, milliseconds. */
  readonly addressCooldownMs: number;
  /** Minimum gap between grants to the same IP (or IPv6 /64), milliseconds. */
  readonly ipCooldownMs: number;
  /** Ceiling on total zaps dispensed in any rolling 24 hours. */
  readonly dailyCap: bigint;
  /** Spendable balance the faucet refuses to go below. */
  readonly reserve: bigint;
  /** Fee rate for faucet payments, zaps per byte. */
  readonly feeRate: number;
}

/**
 * Defaults sized for a testnet where coins are worth nothing and the point is
 * that a developer can get some without asking anybody.
 */
export const DEFAULT_POLICY: FaucetPolicy = {
  amount: 10n * 100_000_000n, // 10 DECKX
  addressCooldownMs: 60 * 60 * 1000, // 1 hour
  ipCooldownMs: 30 * 60 * 1000, // 30 minutes
  dailyCap: 5_000n * 100_000_000n, // 5000 DECKX / day
  reserve: 100n * 100_000_000n, // keep 100 DECKX back
  feeRate: 2,
};

export const FAUCET_VERDICT = {
  OK: 'ok',
  INVALID_ADDRESS: 'invalid-address',
  ADDRESS_COOLDOWN: 'address-cooldown',
  IP_COOLDOWN: 'ip-cooldown',
  DAILY_CAP: 'daily-cap',
  RESERVE: 'reserve',
  EMPTY: 'empty',
} as const;

export type FaucetVerdict = (typeof FAUCET_VERDICT)[keyof typeof FAUCET_VERDICT];

export interface Judgement {
  readonly verdict: FaucetVerdict;
  readonly allowed: boolean;
  readonly reason: string;
  /** Milliseconds until this request would be allowed, when that is knowable. */
  readonly retryAfterMs?: number;
}

/** One dispensed grant. The ledger is the memory that makes limits work. */
export interface Grant {
  readonly address: string;
  /** Normalised client key — see {@link clientKey}. */
  readonly client: string;
  readonly amount: bigint;
  readonly at: number;
  readonly txid: Hex;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/* ─────────────────────────────────────────────────────────────── client ── */

/**
 * Reduce a remote address to the thing worth rate-limiting.
 *
 * Two details that are easy to get wrong and free to get right:
 *
 * **IPv4-mapped IPv6.** Node reports a v4 client on a dual-stack socket as
 * `::ffff:203.0.113.5`. Treating that as distinct from `203.0.113.5` lets one
 * client have two budgets by choosing a stack.
 *
 * **IPv6 is allocated in blocks.** A residential IPv6 customer typically holds
 * a whole /64 and can pick a fresh address from it per request, for free.
 * Limiting the full address therefore limits nothing; the /64 is the unit that
 * corresponds to one subscriber.
 */
export function clientKey(remote: string): string {
  let ip = (remote || '').trim().toLowerCase();
  if (!ip) return 'unknown';

  // Strip a port from `host:port`, but only when it cannot be part of an
  // IPv6 address (which contains several colons).
  const colons = ip.split(':').length - 1;
  if (colons === 1) ip = ip.split(':')[0];

  if (ip.startsWith('[')) ip = ip.slice(1, ip.indexOf(']') > 0 ? ip.indexOf(']') : undefined);
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);

  // IPv4, or something that is not an address at all: use it whole.
  if (!ip.includes(':')) return ip;

  // IPv6 — collapse to the /64 the subscriber actually controls.
  const groups = expandV6(ip).slice(0, 4);
  return `${groups.join(':')}::/64`;
}

function expandV6(ip: string): string[] {
  const [head, tail = ''] = ip.split('::', 2);
  const left = head ? head.split(':') : [];
  const right = ip.includes('::') ? (tail ? tail.split(':') : []) : [];
  const missing = 8 - left.length - right.length;
  const middle = ip.includes('::') ? Array(Math.max(0, missing)).fill('0') : [];
  return [...left, ...middle, ...right].map((g) => (g || '0').padStart(4, '0')).slice(0, 8);
}

/* ─────────────────────────────────────────────────────────────── ledger ── */

/**
 * The record of what has been given out.
 *
 * Persisted, because a faucet that forgets on restart is a faucet you drain by
 * crashing it — and a process that hands out money restarts more often than
 * its operator would like.
 */
export class FaucetLedger {
  #grants: Grant[] = [];

  get size(): number {
    return this.#grants.length;
  }

  all(): readonly Grant[] {
    return this.#grants;
  }

  record(grant: Grant): void {
    this.#grants.push(grant);
  }

  /** Undo the most recent grant for an address — used when a send fails. */
  rollback(txId: Hex): void {
    const at = this.#grants.findLastIndex((g) => g.txid === txId);
    if (at >= 0) this.#grants.splice(at, 1);
  }

  lastFor(address: string, now: number): Grant | undefined {
    return this.#grants.findLast((g) => g.address === address && g.at <= now);
  }

  lastForClient(client: string, now: number): Grant | undefined {
    return this.#grants.findLast((g) => g.client === client && g.at <= now);
  }

  /** Total dispensed in the rolling window ending at `now`. */
  dispensedSince(since: number, now: number): bigint {
    let total = 0n;
    for (const g of this.#grants) if (g.at > since && g.at <= now) total += g.amount;
    return total;
  }

  /** Drop grants old enough that no limit can still refer to them. */
  prune(before: number): number {
    const before_ = this.#grants.length;
    this.#grants = this.#grants.filter((g) => g.at >= before);
    return before_ - this.#grants.length;
  }

  toJSON(): unknown {
    return this.#grants.map((g) => ({ ...g, amount: g.amount.toString() }));
  }

  static fromJSON(raw: unknown): FaucetLedger {
    const ledger = new FaucetLedger();
    if (!Array.isArray(raw)) return ledger;
    for (const row of raw) {
      if (!row || typeof row !== 'object') continue;
      const g = row as Record<string, unknown>;
      if (typeof g.address !== 'string' || typeof g.txid !== 'string') continue;
      ledger.record({
        address: g.address,
        client: String(g.client ?? 'unknown'),
        amount: BigInt(String(g.amount ?? '0')),
        at: Number(g.at ?? 0),
        txid: g.txid as Hex,
      });
    }
    return ledger;
  }
}

/* ───────────────────────────────────────────────────────────── judgement ── */

export interface JudgeInput {
  readonly address: string;
  readonly client: string;
  readonly now: number;
  /** Spendable balance, zaps. Immature coinbase does not count. */
  readonly spendable: bigint;
}

/**
 * Decide whether a request is allowed. Pure: no wallet, no clock, no network.
 *
 * Separated from sending so the limits can be tested exhaustively without
 * mining a block, and so an operator can ask "would this be allowed?" without
 * risking that asking dispenses coins.
 */
export function judgeRequest(
  input: JudgeInput,
  ledger: FaucetLedger,
  policy: FaucetPolicy,
): Judgement {
  const { address, client, now, spendable } = input;

  if (!isValidAddress(address)) {
    return {
      verdict: FAUCET_VERDICT.INVALID_ADDRESS,
      allowed: false,
      reason: `'${address}' is not a valid DeckxCoin address`,
    };
  }

  /*
   * Balance is checked before the cooldowns. A user whose cooldown has not
   * expired should be told to come back later; a user asking of an empty
   * faucet should be told it is empty, because waiting will not help them and
   * the operator is the one who has to act.
   */
  const afterGrant = spendable - policy.amount;
  if (spendable < policy.amount) {
    return {
      verdict: FAUCET_VERDICT.EMPTY,
      allowed: false,
      reason: `faucet holds ${formatDeckx(spendable)}, which is less than the ${formatDeckx(policy.amount)} grant`,
    };
  }
  if (afterGrant < policy.reserve) {
    return {
      verdict: FAUCET_VERDICT.RESERVE,
      allowed: false,
      reason:
        `paying out would leave ${formatDeckx(afterGrant)}, below the ` +
        `${formatDeckx(policy.reserve)} reserve — the faucet needs refilling`,
    };
  }

  const lastToAddress = ledger.lastFor(address, now);
  if (lastToAddress) {
    const waited = now - lastToAddress.at;
    if (waited < policy.addressCooldownMs) {
      return {
        verdict: FAUCET_VERDICT.ADDRESS_COOLDOWN,
        allowed: false,
        reason: `this address was funded ${describe(waited)} ago`,
        retryAfterMs: policy.addressCooldownMs - waited,
      };
    }
  }

  const lastToClient = ledger.lastForClient(client, now);
  if (lastToClient) {
    const waited = now - lastToClient.at;
    if (waited < policy.ipCooldownMs) {
      return {
        verdict: FAUCET_VERDICT.IP_COOLDOWN,
        allowed: false,
        reason: `this network was served ${describe(waited)} ago — a new address does not reset this`,
        retryAfterMs: policy.ipCooldownMs - waited,
      };
    }
  }

  const dispensed = ledger.dispensedSince(now - DAY_MS, now);
  if (dispensed + policy.amount > policy.dailyCap) {
    return {
      verdict: FAUCET_VERDICT.DAILY_CAP,
      allowed: false,
      reason:
        `the faucet has dispensed ${formatDeckx(dispensed)} in the last 24 hours, ` +
        `at its cap of ${formatDeckx(policy.dailyCap)}`,
      retryAfterMs: oldestWindowExpiry(ledger, now),
    };
  }

  return {
    verdict: FAUCET_VERDICT.OK,
    allowed: true,
    reason: `${formatDeckx(policy.amount)} available`,
  };
}

/** When the rolling window will next free up capacity. */
function oldestWindowExpiry(ledger: FaucetLedger, now: number): number | undefined {
  const inWindow = ledger.all().filter((g) => g.at > now - DAY_MS && g.at <= now);
  if (inWindow.length === 0) return undefined;
  const oldest = Math.min(...inWindow.map((g) => g.at));
  return Math.max(0, oldest + DAY_MS - now);
}

function describe(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 1) return 'less than a minute';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.round(minutes / 60);
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/* ─────────────────────────────────────────────────────────────── faucet ── */

export interface FaucetOptions {
  readonly wallet: Wallet;
  /** Live chain view. Called per request — the balance moves. */
  readonly chain: () => { state: WorldState; height: number; time: number };
  /**
   * Broadcast a signed transaction. Returns an error string on rejection.
   *
   * Allowed to be async, because a real one is: the faucet usually talks to a
   * node over HTTP rather than holding one in-process. That await point is
   * exactly where concurrent requests interleave, which is what the send queue
   * below exists to prevent.
   */
  readonly broadcast: (
    tx: Transaction,
  ) => { ok: boolean; error?: string } | Promise<{ ok: boolean; error?: string }>;
  readonly policy?: Partial<FaucetPolicy>;
  readonly ledger?: FaucetLedger;
  /** Injectable for tests; defaults to `Date.now`. */
  readonly now?: () => number;
  /** Called after every state change, so a caller can persist the ledger. */
  readonly onChange?: (ledger: FaucetLedger) => void;
}

export interface FaucetResult extends Judgement {
  readonly txid?: Hex;
  readonly amount?: string;
  readonly amountPretty?: string;
  readonly fee?: string;
}

export class Faucet {
  readonly policy: FaucetPolicy;
  readonly ledger: FaucetLedger;
  readonly wallet: Wallet;
  readonly #chain: FaucetOptions['chain'];
  readonly #broadcast: FaucetOptions['broadcast'];
  readonly #now: () => number;
  readonly #onChange?: (ledger: FaucetLedger) => void;

  /**
   * Tail of the send queue. Every request awaits the previous one, so exactly
   * one send is ever in flight and each reads the state the last one left.
   */
  #queue: Promise<unknown> = Promise.resolve();

  constructor(opts: FaucetOptions) {
    this.policy = { ...DEFAULT_POLICY, ...opts.policy };
    this.ledger = opts.ledger ?? new FaucetLedger();
    this.wallet = opts.wallet;
    this.#chain = opts.chain;
    this.#broadcast = opts.broadcast;
    this.#now = opts.now ?? Date.now;
    this.#onChange = opts.onChange;
  }

  /** The address the faucet pays from, for operators topping it up. */
  get address(): string {
    return this.wallet.addresses()[0] ?? '';
  }

  spendable(): bigint {
    const { state, height } = this.#chain();
    return this.wallet.balance(state, height).spendable;
  }

  /** Would this be allowed right now? Never dispenses. */
  check(address: string, remote: string): Judgement {
    return judgeRequest(
      { address, client: clientKey(remote), now: this.#now(), spendable: this.spendable() },
      this.ledger,
      this.policy,
    );
  }

  /**
   * Serve a request.
   *
   * Serialised: the judgement is re-made inside the queue, against the balance
   * left by the previous send. Judging outside the queue would let a hundred
   * simultaneous requests all see a full faucet and all be approved.
   */
  request(address: string, remote: string): Promise<FaucetResult> {
    const run = this.#queue.then(
      () => this.#serve(address, remote),
      () => this.#serve(address, remote),
    );
    // Keep the chain alive even when a request throws, or one failure wedges
    // the faucet permanently.
    this.#queue = run.catch(() => {});
    return run;
  }

  async #serve(address: string, remote: string): Promise<FaucetResult> {
    const client = clientKey(remote);
    const now = this.#now();
    const { state, height, time } = this.#chain();
    const spendable = this.wallet.balance(state, height).spendable;

    const judgement = judgeRequest({ address, client, now, spendable }, this.ledger, this.policy);
    if (!judgement.allowed) return judgement;

    const built = this.wallet.send({
      state,
      tipHeight: height,
      tipTime: time,
      to: address,
      amount: this.policy.amount,
      feeRate: this.policy.feeRate,
    });
    if (!built.ok) {
      return {
        verdict: FAUCET_VERDICT.EMPTY,
        allowed: false,
        reason: `faucet could not build a payment: ${built.error}`,
      };
    }

    const id = txid(built.transaction!);

    /*
     * Recorded before broadcasting. If the node rejects it the grant is rolled
     * back below; the alternative ordering — broadcast, then record — pays
     * twice whenever two requests interleave, and paying twice is the failure
     * that empties a faucet.
     */
    this.ledger.record({ address, client, amount: this.policy.amount, at: now, txid: id });

    const sent = await this.#broadcast(built.transaction!);
    if (!sent.ok) {
      this.ledger.rollback(id);
      return {
        verdict: FAUCET_VERDICT.EMPTY,
        allowed: false,
        reason: `node rejected the faucet payment: ${sent.error ?? 'unknown reason'}`,
      };
    }

    this.ledger.prune(now - DAY_MS * 2);
    this.#onChange?.(this.ledger);

    return {
      ...judgement,
      txid: id,
      amount: this.policy.amount.toString(),
      amountPretty: formatDeckx(this.policy.amount),
      fee: built.fee!.toString(),
    };
  }

  /** Operator-facing summary. Safe to expose publicly — no keys, no addresses of others. */
  info() {
    const now = this.#now();
    const spendable = this.spendable();
    const dispensed = this.ledger.dispensedSince(now - DAY_MS, now);
    return {
      address: this.address,
      amount: this.policy.amount.toString(),
      amountPretty: formatDeckx(this.policy.amount),
      balance: spendable.toString(),
      balancePretty: formatDeckx(spendable),
      reserve: formatDeckx(this.policy.reserve),
      addressCooldownMs: this.policy.addressCooldownMs,
      ipCooldownMs: this.policy.ipCooldownMs,
      dispensed24h: formatDeckx(dispensed),
      dailyCap: formatDeckx(this.policy.dailyCap),
      remaining24h: formatDeckx(
        this.policy.dailyCap > dispensed ? this.policy.dailyCap - dispensed : 0n,
      ),
      grants: this.ledger.size,
      // An operator watching one number should watch this one.
      healthy: spendable - this.policy.amount >= this.policy.reserve,
    };
  }
}
