/**
 * The public gateway.
 *
 * This is the only component in the repository that is meant to be reachable
 * from the open internet, so the tests are about what it refuses, what it
 * caches, and whether the refusal survives someone adding a method to the node.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FORBIDDEN_METHODS,
  Gateway,
  PUBLIC_METHODS,
  RateLimiter,
  ResponseCache,
} from '../src/node/gateway.ts';
import { RPC_METHODS } from '../src/node/rpc.ts';

/** A gateway over a fake node, with a clock the test drives. */
function rigGateway(
  opts: {
    call?: (method: string, params: Record<string, unknown>) => Promise<unknown>;
    ratePerMinute?: number;
  } = {},
) {
  let clock = 1_700_000_000_000;
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];

  const gateway = new Gateway({
    call: async (method, params) => {
      calls.push({ method, params });
      if (opts.call) return opts.call(method, params);
      return { method, params, servedAt: clock };
    },
    now: () => clock,
    ratePerMinute: opts.ratePerMinute ?? 600,
    limiter: new RateLimiter(opts.ratePerMinute ?? 600, opts.ratePerMinute ?? 600),
  });

  return {
    gateway,
    calls,
    tick: (ms: number) => {
      clock += ms;
    },
  };
}

/* ───────────────────────────────────────────────────────── allowlist ── */

test('a read method is forwarded to the node', async () => {
  const { gateway, calls } = rigGateway();
  const res = await gateway.rpc('getblockchaininfo', {}, '203.0.113.5');

  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'getblockchaininfo');
});

test('every dangerous method is refused', async () => {
  const { gateway, calls } = rigGateway();

  for (const method of FORBIDDEN_METHODS) {
    const res = await gateway.rpc(method, { count: 100, address: 'dxc1q' }, '203.0.113.5');
    assert.equal(res.status, 403, `${method} must not be reachable`);
  }
  assert.equal(calls.length, 0, 'a refused method must never reach the node');
});

test('the gateway is an allowlist, so a new node method is not public by default', () => {
  /*
   * The test that earns its keep later. Someone adds a method to the node's
   * RPC; with a denylist it becomes internet-reachable the moment it exists.
   * This asserts the opposite property: every publicly reachable method was
   * put on the list deliberately.
   */
  const nodeMethods = RPC_METHODS.map((line) => line.split(' ')[0]);

  for (const method of Object.keys(PUBLIC_METHODS)) {
    assert.ok(nodeMethods.includes(method), `gateway exposes '${method}', which the node does not have`);
  }

  const notExposed = nodeMethods.filter((m) => !Object.hasOwn(PUBLIC_METHODS, m));
  assert.ok(notExposed.length > 0, 'the node must have methods the gateway does not expose');

  for (const dangerous of FORBIDDEN_METHODS) {
    assert.ok(!Object.hasOwn(PUBLIC_METHODS, dangerous), `${dangerous} must never be on the allowlist`);
  }
});

test('an unknown method is refused with the list of what is available', async () => {
  const { gateway } = rigGateway();
  const res = await gateway.rpc('rm-rf', {}, '203.0.113.5');

  assert.equal(res.status, 403);
  const body = res.body as { error: { available: string[] } };
  assert.ok(body.error.available.includes('getblock'));
});

/* ───────────────────────────────────────────────────────────── cache ── */

test('a repeated query is served from cache without touching the node', async () => {
  const { gateway, calls } = rigGateway();

  await gateway.rpc('getblockchaininfo', {}, '203.0.113.5');
  const second = await gateway.rpc('getblockchaininfo', {}, '198.51.100.7');

  assert.equal(calls.length, 1, 'the node must be asked once');
  assert.equal(second.cached, true);
});

test('the cache is keyed by parameters, not just by method', async () => {
  /*
   * The quiet bug: `getblock` for one hash serving the cached body of
   * `getblock` for another, so an explorer shows the wrong block to whoever
   * asked second.
   */
  const { gateway, calls } = rigGateway();
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);

  const first = (await gateway.rpc('getblock', { hash: a }, 'x')).body as { result: { params: unknown } };
  const second = (await gateway.rpc('getblock', { hash: b }, 'x')).body as { result: { params: unknown } };

  assert.equal(calls.length, 2, 'different parameters are different questions');
  assert.deepEqual(first.result.params, { hash: a });
  assert.deepEqual(second.result.params, { hash: b });
});

test('parameter order does not create a second cache entry', async () => {
  const { gateway, calls } = rigGateway();
  await gateway.rpc('getblock', { hash: 'a'.repeat(64), verbose: true }, 'x');
  await gateway.rpc('getblock', { verbose: true, hash: 'a'.repeat(64) }, 'x');

  assert.equal(calls.length, 1);
});

test('a cache entry expires', async () => {
  const { gateway, calls, tick } = rigGateway();

  await gateway.rpc('getbestblockhash', {}, 'x');
  tick(PUBLIC_METHODS.getbestblockhash + 1);
  await gateway.rpc('getbestblockhash', {}, 'x');

  assert.equal(calls.length, 2, 'the tip moves, so its cache must expire');
});

test('tip-derived answers are cached for less time than immutable ones', () => {
  // A block at a hash never changes; the tip changes every few minutes.
  assert.ok(PUBLIC_METHODS.getblock > PUBLIC_METHODS.getbestblockhash * 5);
});

test('errors are not cached', async () => {
  /*
   * Caching a failure turns one bad second at the node into a full TTL of a
   * broken explorer for everybody.
   */
  let fail = true;
  const { gateway, calls } = rigGateway({
    call: async () => {
      if (fail) throw new Error('node is restarting');
      return { ok: true };
    },
  });

  const failed = (await gateway.rpc('getinfo', {}, 'x')).body as { error?: { message: string } };
  assert.match(failed.error!.message, /restarting/);

  fail = false;
  const recovered = (await gateway.rpc('getinfo', {}, 'x')).body as { result?: unknown };
  assert.deepEqual(recovered.result, { ok: true });
  assert.equal(calls.length, 2);
});

test('the cache evicts rather than growing without bound', () => {
  const cache = new ResponseCache(10);
  for (let i = 0; i < 50; i++) cache.set(`k${i}`, i, 60_000, 1000);
  assert.equal(cache.stats.size, 10);
});

/* ──────────────────────────────────────────────────────── rate limit ── */

test('a client exceeding its budget is refused, and told to retry', async () => {
  const { gateway } = rigGateway({ ratePerMinute: 5 });

  // Distinct parameters, so nothing is answered from cache.
  const results = [];
  for (let i = 0; i < 8; i++) {
    results.push(await gateway.rpc('getblockhash', { height: i }, '203.0.113.5'));
  }

  const refused = results.filter((r) => r.status === 429);
  assert.ok(refused.length >= 2, 'a client over budget must be refused');
  assert.equal(refused[0].retryAfterSeconds, 5);
});

test('one noisy client does not affect another', async () => {
  const { gateway } = rigGateway({ ratePerMinute: 5 });

  for (let i = 0; i < 10; i++) await gateway.rpc('getblockhash', { height: i }, '203.0.113.5');
  const other = await gateway.rpc('getblockhash', { height: 999 }, '198.51.100.7');

  assert.equal(other.status, 200, 'limits are per client');
});

test('a cached answer is served even to a client over its limit', async () => {
  /*
   * A cached response costs the node nothing, so refusing it would punish the
   * visitor without protecting anything. The limiter exists to shield the
   * node, not to ration bytes.
   */
  const { gateway } = rigGateway({ ratePerMinute: 3 });

  await gateway.rpc('getinfo', {}, '203.0.113.5');
  for (let i = 0; i < 10; i++) await gateway.rpc('getblockhash', { height: i }, '203.0.113.5');

  const cached = await gateway.rpc('getinfo', {}, '203.0.113.5');
  assert.equal(cached.status, 200);
  assert.equal(cached.cached, true);
});

test('the bucket refills over time', () => {
  const limiter = new RateLimiter(5, 60); // 5 burst, 60/minute
  let now = 1_000_000;

  for (let i = 0; i < 5; i++) assert.equal(limiter.take('c', now), true);
  assert.equal(limiter.take('c', now), false, 'burst is spent');

  now += 1_000; // one second → one token at 60/min
  assert.equal(limiter.take('c', now), true);
});

test('a burst is allowed, which a fixed window would refuse', () => {
  /*
   * A page load fires several queries at once. A fixed window that allows N
   * per minute refuses the second half of an honest page load if it happens to
   * land near the boundary; a token bucket does not.
   */
  const limiter = new RateLimiter(20, 20);
  const now = 1_000_000;
  for (let i = 0; i < 20; i++) {
    assert.equal(limiter.take('c', now), true, `burst request ${i} must be allowed`);
  }
});

test('idle clients are forgotten', () => {
  const limiter = new RateLimiter(10, 60);
  limiter.take('a', 1_000_000);
  assert.equal(limiter.size, 1);

  limiter.prune(1_000_000 + 60_000);
  assert.equal(limiter.size, 0, 'a fully refilled bucket carries no information');
});
