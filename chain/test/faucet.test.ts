/**
 * The faucet.
 *
 * A faucet is an unauthenticated endpoint that gives away money, so the tests
 * are almost entirely about refusing. The happy path is one test; the rest are
 * the ways somebody empties it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  clientKey,
  DEFAULT_POLICY,
  FAUCET_VERDICT,
  Faucet,
  FaucetLedger,
  judgeRequest,
  type FaucetPolicy,
} from '../src/node/faucet.ts';
import { HdWallet } from '../src/wallet/hd.ts';
import { Wallet } from '../src/wallet/wallet.ts';
import { signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { keyPairFromSeed } from '../src/crypto.ts';
import { COINBASE_MATURITY, type Utxo } from '../src/state.ts';
import { advance, rig } from './helpers.ts';

const DECKX = ZAPS_PER_DECKX;

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

/** A faucet wallet holding `amount`, on a real regtest chain. */
function fundedFaucet(amount = 2_000n * DECKX) {
  const wallet = new Wallet({ hd: HdWallet.fromMnemonic(MNEMONIC) });
  const { chain, miner } = rig('faucet/miner');
  const target = wallet.hd.receiving(0);

  /*
   * One coinbase is ~199.77 DECKX, so anything above that has to be gathered
   * from several. Mine until the miner holds enough mature coin, then sweep it
   * into a single faucet output.
   */
  const mature = () =>
    chain.state
      .utxosFor(miner.address)
      .filter((u) => !u.coinbase || chain.height - u.height >= COINBASE_MATURITY)
      .sort((a, b) => (a.value > b.value ? -1 : 1));

  const FEE = 100_000n;
  while (mature().reduce((s, u) => s + u.value, 0n) < amount + FEE) {
    advance(chain, miner.address, COINBASE_MATURITY);
  }

  const coins: Utxo[] = [];
  let gathered = 0n;
  for (const u of mature()) {
    coins.push(u);
    gathered += u.value;
    if (gathered >= amount + FEE) break;
  }

  const funding = signTx(
    transferTx({
      inputs: coins.map((u) => ({ txid: u.txid, vout: u.vout })),
      outputs: [
        { value: amount.toString(), address: target.address },
        { value: (gathered - amount - FEE).toString(), address: miner.address },
      ],
    }),
    miner,
    coins.map((u) => ({ value: u.value, address: u.address })),
  );

  const { result } = chain.mineBlock([funding], miner.address, {
    time: chain.tip.header.time + 600,
  });
  assert.ok(result.ok, `funding rejected: ${result.error}`);
  advance(chain, miner.address, 1);

  return { wallet, chain, miner };
}

/**
 * A faucet wired to a chain, with a clock the test controls and a broadcast
 * that mines immediately — so a second request sees the first one's change.
 */
function rigFaucet(opts: { amount?: bigint; policy?: Partial<FaucetPolicy> } = {}) {
  const { wallet, chain, miner } = fundedFaucet(opts.amount);
  let clock = 1_700_000_000_000;
  const broadcasts: string[] = [];
  let failNext: string | undefined;

  const faucet = new Faucet({
    wallet,
    chain: () => ({ state: chain.state, height: chain.height, time: chain.tip.header.time }),
    /*
     * Deliberately async, with a real await before the state changes. A
     * synchronous broadcast would make every request run to completion without
     * yielding, and the concurrency test below would pass with the send queue
     * deleted — proving nothing.
     */
    broadcast: async (tx) => {
      await new Promise((r) => setTimeout(r, 1));
      if (failNext) {
        const error = failNext;
        failNext = undefined;
        return { ok: false, error };
      }
      const { result } = chain.mineBlock([tx], miner.address, {
        time: chain.tip.header.time + 600,
      });
      if (!result.ok) return { ok: false, error: result.error };
      broadcasts.push(txid(tx));
      return { ok: true };
    },
    now: () => clock,
    policy: opts.policy,
  });

  return {
    faucet,
    wallet,
    chain,
    broadcasts,
    advanceClock: (ms: number) => {
      clock += ms;
    },
    failNextBroadcast: (reason: string) => {
      failNext = reason;
    },
  };
}

const recipient = (n: number) => keyPairFromSeed(`faucet/recipient/${n}`).address;

/* ────────────────────────────────────────────────────── client keys ── */

test('an IPv4-mapped IPv6 address is the same client as the plain IPv4', () => {
  // Otherwise one client gets two budgets by choosing a network stack.
  assert.equal(clientKey('::ffff:203.0.113.5'), '203.0.113.5');
  assert.equal(clientKey('203.0.113.5'), '203.0.113.5');
  assert.equal(clientKey('203.0.113.5:51820'), '203.0.113.5');
});

test('IPv6 clients are limited by /64, not by address', () => {
  /*
   * A residential IPv6 subscriber holds a whole /64 and can source a fresh
   * address from it per request at no cost. Limiting the full address limits
   * nothing at all.
   */
  const a = clientKey('2001:db8:1234:5678:aaaa:bbbb:cccc:dddd');
  const b = clientKey('2001:db8:1234:5678:1111:2222:3333:4444');
  assert.equal(a, b, 'addresses in one /64 are one client');

  const elsewhere = clientKey('2001:db8:1234:9999::1');
  assert.notEqual(a, elsewhere, 'a different /64 is a different client');
});

test('compressed IPv6 forms normalise to the same key', () => {
  assert.equal(clientKey('2001:db8::1'), clientKey('2001:0db8:0000:0000:0000:0000:0000:0001'));
  assert.equal(clientKey('[2001:db8::1]'), clientKey('2001:db8::1'));
});

/* ───────────────────────────────────────────────────────── judgement ── */

const base = (over: Partial<Parameters<typeof judgeRequest>[0]> = {}) => ({
  address: recipient(1),
  client: '203.0.113.5',
  now: 1_000_000,
  spendable: 10_000n * DECKX,
  ...over,
});

test('a well-formed first request is allowed', () => {
  const verdict = judgeRequest(base(), new FaucetLedger(), DEFAULT_POLICY);
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.verdict, FAUCET_VERDICT.OK);
});

test('a malformed address is refused before anything else is considered', () => {
  const verdict = judgeRequest(base({ address: 'not-an-address' }), new FaucetLedger(), DEFAULT_POLICY);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.verdict, FAUCET_VERDICT.INVALID_ADDRESS);
});

test('a second request from the same address is refused, with a time to retry', () => {
  const ledger = new FaucetLedger();
  ledger.record({
    address: recipient(1),
    client: 'other',
    amount: DEFAULT_POLICY.amount,
    at: 1_000_000 - 60_000,
    txid: 'a'.repeat(64),
  });

  const verdict = judgeRequest(base(), ledger, DEFAULT_POLICY);
  assert.equal(verdict.verdict, FAUCET_VERDICT.ADDRESS_COOLDOWN);
  assert.equal(verdict.retryAfterMs, DEFAULT_POLICY.addressCooldownMs - 60_000);
});

test('a fresh address from a served network is still refused', () => {
  /*
   * The limit that actually does the work. Addresses are free, so a per-address
   * cooldown alone stops nothing but a double-click.
   */
  const ledger = new FaucetLedger();
  ledger.record({
    address: recipient(1),
    client: '203.0.113.5',
    amount: DEFAULT_POLICY.amount,
    at: 1_000_000 - 60_000,
    txid: 'a'.repeat(64),
  });

  const verdict = judgeRequest(base({ address: recipient(2) }), ledger, DEFAULT_POLICY);
  assert.equal(verdict.verdict, FAUCET_VERDICT.IP_COOLDOWN);
  assert.match(verdict.reason, /a new address does not reset this/);
});

test('the daily cap catches what a proxy pool gets past the per-IP limit', () => {
  const policy: FaucetPolicy = { ...DEFAULT_POLICY, dailyCap: 30n * DECKX, amount: 10n * DECKX };
  const ledger = new FaucetLedger();

  // Three grants, every one from a different address and a different network.
  for (let i = 0; i < 3; i++) {
    ledger.record({
      address: recipient(i),
      client: `198.51.100.${i}`,
      amount: 10n * DECKX,
      at: 1_000_000 - 1000,
      txid: String(i).repeat(64),
    });
  }

  const verdict = judgeRequest(base({ address: recipient(9), client: '198.51.100.9' }), ledger, policy);
  assert.equal(verdict.verdict, FAUCET_VERDICT.DAILY_CAP);
  assert.ok(verdict.retryAfterMs! > 0, 'the rolling window must say when capacity returns');
});

test('the daily window rolls — it is not a calendar reset', () => {
  /*
   * A midnight reset teaches every drainer to queue up for midnight. A rolling
   * window means capacity returns gradually and there is no moment to target.
   */
  const policy: FaucetPolicy = { ...DEFAULT_POLICY, dailyCap: 10n * DECKX, amount: 10n * DECKX };
  const ledger = new FaucetLedger();
  const DAY = 24 * 60 * 60 * 1000;

  ledger.record({
    address: recipient(1),
    client: 'x',
    amount: 10n * DECKX,
    at: 1_000_000,
    txid: 'a'.repeat(64),
  });

  // One millisecond short of a day later: still counted.
  const stillCapped = judgeRequest(
    base({ address: recipient(2), client: 'y', now: 1_000_000 + DAY - 1 }),
    ledger,
    policy,
  );
  assert.equal(stillCapped.verdict, FAUCET_VERDICT.DAILY_CAP);

  // A millisecond past: the grant has left the window.
  const freed = judgeRequest(
    base({ address: recipient(2), client: 'y', now: 1_000_000 + DAY + 1 }),
    ledger,
    policy,
  );
  assert.equal(freed.allowed, true);
});

test('the reserve stops the last coins going out', () => {
  const policy: FaucetPolicy = { ...DEFAULT_POLICY, amount: 10n * DECKX, reserve: 100n * DECKX };

  const above = judgeRequest(base({ spendable: 111n * DECKX }), new FaucetLedger(), policy);
  assert.equal(above.allowed, true);

  const below = judgeRequest(base({ spendable: 105n * DECKX }), new FaucetLedger(), policy);
  assert.equal(below.verdict, FAUCET_VERDICT.RESERVE);
  assert.match(below.reason, /needs refilling/);
});

test('an empty faucet says it is empty, not that you are rate-limited', () => {
  // The distinction matters: one is fixed by waiting, the other by an operator.
  const verdict = judgeRequest(base({ spendable: 1n }), new FaucetLedger(), DEFAULT_POLICY);
  assert.equal(verdict.verdict, FAUCET_VERDICT.EMPTY);
  assert.equal(verdict.retryAfterMs, undefined);
});

/* ──────────────────────────────────────────────────────────── ledger ── */

test('the ledger survives a restart', () => {
  /*
   * A faucet that forgets its grants on restart is drained by crashing it, and
   * a process handing out money restarts more often than its operator likes.
   */
  const ledger = new FaucetLedger();
  ledger.record({
    address: recipient(1),
    client: '203.0.113.5',
    amount: 10n * DECKX,
    at: 1_000_000,
    txid: 'a'.repeat(64),
  });

  const revived = FaucetLedger.fromJSON(JSON.parse(JSON.stringify(ledger.toJSON())));
  assert.equal(revived.size, 1);
  assert.equal(revived.lastFor(recipient(1), 2_000_000)!.amount, 10n * DECKX);

  const verdict = judgeRequest(base({ now: 1_060_000 }), revived, DEFAULT_POLICY);
  assert.equal(verdict.verdict, FAUCET_VERDICT.ADDRESS_COOLDOWN, 'cooldowns must survive too');
});

test('pruning keeps grants the limits can still refer to', () => {
  const ledger = new FaucetLedger();
  const DAY = 24 * 60 * 60 * 1000;
  for (let i = 0; i < 5; i++) {
    ledger.record({
      address: recipient(i),
      client: `c${i}`,
      amount: DECKX,
      at: 1_000_000 + i * DAY,
      txid: String(i).repeat(64),
    });
  }

  const dropped = ledger.prune(1_000_000 + 3 * DAY);
  assert.equal(dropped, 3);
  assert.equal(ledger.size, 2);
});

/* ─────────────────────────────────────────────────────── dispensing ── */

test('a request pays out, and the coins arrive', async () => {
  const { faucet, chain } = rigFaucet({ policy: { amount: 25n * DECKX } });
  const to = recipient(1);

  const result = await faucet.request(to, '203.0.113.5');
  assert.equal(result.allowed, true, result.reason);
  assert.ok(result.txid, 'a payout must return a txid the user can check');
  assert.equal(chain.state.balanceOf(to), 25n * DECKX);
});

test('concurrent requests do not double-spend the faucet', async () => {
  /*
   * The bug this file exists to not have. Five requests arriving together all
   * read the same UTXO set; without serialisation they all select the same
   * coin and four of the five transactions conflict.
   *
   * Each comes from a different network so the rate limits do not mask the
   * result — every one of these *should* be paid.
   */
  const { faucet, chain, broadcasts } = rigFaucet({ policy: { amount: 5n * DECKX } });

  const results = await Promise.all(
    [0, 1, 2, 3, 4].map((i) => faucet.request(recipient(i), `198.51.100.${i}`)),
  );

  for (const [i, r] of results.entries()) {
    assert.equal(r.allowed, true, `request ${i} refused: ${r.reason}`);
  }
  assert.equal(new Set(broadcasts).size, 5, 'five distinct transactions must reach the chain');
  for (let i = 0; i < 5; i++) {
    assert.equal(chain.state.balanceOf(recipient(i)), 5n * DECKX, `recipient ${i} was not paid`);
  }
});

test('a rejected broadcast does not consume the requester’s cooldown', async () => {
  const { faucet, failNextBroadcast } = rigFaucet({ policy: { amount: 5n * DECKX } });
  const to = recipient(1);

  failNextBroadcast('mempool full');
  const failed = await faucet.request(to, '203.0.113.5');
  assert.equal(failed.allowed, false);
  assert.match(failed.reason, /mempool full/);
  assert.equal(faucet.ledger.size, 0, 'a grant that never went out must be rolled back');

  // The user can immediately try again — they were never paid.
  const retry = await faucet.request(to, '203.0.113.5');
  assert.equal(retry.allowed, true, retry.reason);
});

test('a failed request does not wedge the queue', async () => {
  // A rejected send leaves a rejected promise at the tail of the chain. If the
  // next request awaits it without catching, the faucet stops forever.
  const { faucet, failNextBroadcast } = rigFaucet({ policy: { amount: 5n * DECKX } });

  failNextBroadcast('transient');
  const [first, second] = await Promise.all([
    faucet.request(recipient(1), '198.51.100.1'),
    faucet.request(recipient(2), '198.51.100.2'),
  ]);

  assert.equal(first.allowed, false);
  assert.equal(second.allowed, true, `the faucet stopped serving: ${second.reason}`);
});

test('the same address is refused a second time, then served once the cooldown passes', async () => {
  const { faucet, advanceClock } = rigFaucet({
    policy: { amount: 5n * DECKX, addressCooldownMs: 3_600_000, ipCooldownMs: 0 },
  });
  const to = recipient(1);

  assert.equal((await faucet.request(to, '203.0.113.5')).allowed, true);

  const again = await faucet.request(to, '203.0.113.5');
  assert.equal(again.verdict, FAUCET_VERDICT.ADDRESS_COOLDOWN);
  assert.ok(again.retryAfterMs! > 0);

  advanceClock(3_600_001);
  const later = await faucet.request(to, '203.0.113.5');
  assert.equal(later.allowed, true, later.reason);
});

test('check() reports the verdict without dispensing', () => {
  const { faucet, chain } = rigFaucet({ policy: { amount: 5n * DECKX } });
  const to = recipient(1);

  const before = chain.height;
  const verdict = faucet.check(to, '203.0.113.5');

  assert.equal(verdict.allowed, true);
  assert.equal(faucet.ledger.size, 0, 'asking must not dispense');
  assert.equal(chain.height, before);
  assert.equal(chain.state.balanceOf(to), 0n);
});

test('the faucet drains down to its reserve and then stops', async () => {
  /*
   * The end state that matters: a faucet that has given away what it can says
   * so clearly, rather than emitting build errors at everybody until an
   * operator notices.
   */
  const { faucet } = rigFaucet({
    amount: 100n * DECKX,
    policy: {
      amount: 20n * DECKX,
      reserve: 30n * DECKX,
      addressCooldownMs: 0,
      ipCooldownMs: 0,
      dailyCap: 10_000n * DECKX,
    },
  });

  let paid = 0;
  let last = '';
  for (let i = 0; i < 10; i++) {
    const r = await faucet.request(recipient(i), `198.51.100.${i}`);
    if (r.allowed) paid++;
    else {
      last = r.verdict;
      break;
    }
  }

  assert.ok(paid >= 3, `expected several payouts before the reserve, got ${paid}`);
  assert.equal(last, FAUCET_VERDICT.RESERVE);
  assert.equal(faucet.info().healthy, false, 'an operator watching one flag should see this');
});

test('info() exposes what an operator needs and no key material', () => {
  const { faucet } = rigFaucet({ policy: { amount: 5n * DECKX } });
  const info = faucet.info();

  assert.ok(info.address.startsWith('dxc1'));
  assert.equal(info.healthy, true);
  assert.match(info.remaining24h, /DECKX/);

  const serialised = JSON.stringify(info);
  assert.ok(!serialised.includes('abandon'), 'the mnemonic must never appear');
  assert.ok(!/"(privateKey|key|seed|mnemonic)"/.test(serialised), 'no key material in the report');
});
