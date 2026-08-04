/**
 * The public gateway.
 *
 * A node's RPC is unauthenticated and can mine, dial peers and stop the
 * process. It binds to loopback for that reason. But a live explorer needs
 * *something* reachable from a browser, and "just expose the RPC port" is how
 * a testnet becomes somebody else's regtest.
 *
 * This is the thing that faces the internet instead: a narrow, read-only,
 * cached, rate-limited front end that forwards a fixed set of queries to a
 * node on localhost and refuses everything else.
 *
 * ── The allowlist is a list of what is allowed ────────────────────────────
 * Not a list of what is blocked. The difference decides what happens the day
 * somebody adds a method to the node: with a denylist, the new method is
 * public the moment it exists and nobody notices until it matters. With an
 * allowlist, it is unreachable until a human adds it here on purpose. The same
 * reasoning is why `stop`, `generate` and `addnode` are not merely absent but
 * named in a test that fails if they ever become reachable.
 *
 * ── Caching is not an optimisation here ───────────────────────────────────
 * An explorer that hits the node once per page view falls over the first time
 * it is linked anywhere. The cache is what keeps a single small VPS serving a
 * front page, and its TTL is short because the tip moves.
 *
 * ── What this deliberately does not do ────────────────────────────────────
 * No TLS and no authentication. Both belong in the reverse proxy in front —
 * nginx or Caddy already do them properly, and a hand-rolled version here
 * would be worse while looking equivalent.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { clientKey, type Faucet } from './faucet.ts';

/* ───────────────────────────────────────────────────────────── allowlist ── */

/**
 * Methods reachable through the gateway, with how long each may be cached.
 *
 * Immutable answers (a block at a hash, a transaction in a block) can be held
 * for a long time; anything derived from the tip cannot.
 */
export const PUBLIC_METHODS: Readonly<Record<string, number>> = {
  getinfo: 3_000,
  getblockchaininfo: 3_000,
  getbestblockhash: 2_000,
  getblockhash: 10_000,
  getblock: 60_000,
  getblockheader: 60_000,
  gettransaction: 5_000,
  getbalance: 5_000,
  listunspent: 5_000,
  getcontract: 5_000,
  getrawmempool: 2_000,
  getmempoolinfo: 2_000,
  auditsupply: 30_000,
  // Peer *counts* are in getinfo. getpeerinfo lists addresses, which is a map
  // of the network's topology handed to anyone who asks, so it stays private.
};

/**
 * Methods that must never be reachable, named explicitly.
 *
 * The allowlist already excludes them. This exists so that a test can assert
 * on the names rather than on the absence of names, and so the reason each one
 * is dangerous is written down next to it.
 */
export const FORBIDDEN_METHODS: readonly string[] = [
  'generate', // mints coins
  'submitblock', // rewrites the chain
  'addnode', // makes the node dial anywhere the caller likes
  'sync', // work the caller can trigger without limit
  'getpeerinfo', // network topology
  'listbanned', // ditto
];

/* ─────────────────────────────────────────────────────────────── cache ── */

interface CacheEntry {
  readonly value: unknown;
  readonly until: number;
}

/**
 * A response cache keyed by method *and* parameters.
 *
 * Keying by method alone is a real and quiet bug: `getblock` for one hash
 * would serve the cached body of `getblock` for another, and an explorer would
 * show the wrong block to whoever asked second.
 */
export class ResponseCache {
  readonly #entries = new Map<string, CacheEntry>();
  readonly #max: number;
  #hits = 0;
  #misses = 0;

  constructor(max = 500) {
    this.#max = max;
  }

  static key(method: string, params: Record<string, unknown>): string {
    // Sorted so {a,b} and {b,a} are one entry rather than two.
    const stable = Object.keys(params)
      .sort()
      .map((k) => `${k}=${JSON.stringify(params[k])}`)
      .join('&');
    return `${method}?${stable}`;
  }

  get(key: string, now: number): unknown | undefined {
    const entry = this.#entries.get(key);
    if (!entry) {
      this.#misses++;
      return undefined;
    }
    if (entry.until <= now) {
      this.#entries.delete(key);
      this.#misses++;
      return undefined;
    }
    this.#hits++;
    return entry.value;
  }

  set(key: string, value: unknown, ttlMs: number, now: number): void {
    if (ttlMs <= 0) return;
    // Oldest-first eviction. Map preserves insertion order, so the first key is
    // the least recently *added* — good enough for a cache whose entries all
    // expire within a minute anyway.
    if (this.#entries.size >= this.#max) {
      const oldest = this.#entries.keys().next().value;
      if (oldest !== undefined) this.#entries.delete(oldest);
    }
    this.#entries.set(key, { value, until: now + ttlMs });
  }

  get stats() {
    return { size: this.#entries.size, hits: this.#hits, misses: this.#misses };
  }
}

/* ────────────────────────────────────────────────────────── rate limit ── */

/**
 * A token bucket per client.
 *
 * Bursty by design: a page load fires several queries at once and should not
 * be throttled, while a loop pulling continuously should be. A fixed window
 * gets this backwards — it allows a burst of the entire quota and then refuses
 * everything, including the second half of an honest page load.
 */
export class RateLimiter {
  readonly capacity: number;
  readonly refillPerMs: number;
  readonly #buckets = new Map<string, { tokens: number; at: number }>();

  constructor(capacity = 60, perMinute = 60) {
    this.capacity = capacity;
    this.refillPerMs = perMinute / 60_000;
  }

  /** Returns false when the caller is over budget. */
  take(client: string, now: number, cost = 1): boolean {
    const bucket = this.#buckets.get(client) ?? { tokens: this.capacity, at: now };
    const refill = Math.max(0, now - bucket.at) * this.refillPerMs;
    const tokens = Math.min(this.capacity, bucket.tokens + refill);

    if (tokens < cost) {
      this.#buckets.set(client, { tokens, at: now });
      return false;
    }
    this.#buckets.set(client, { tokens: tokens - cost, at: now });
    return true;
  }

  /** Drop buckets that have refilled completely; they carry no information. */
  prune(now: number): void {
    const full = this.capacity / this.refillPerMs;
    for (const [client, bucket] of this.#buckets) {
      if (now - bucket.at > full) this.#buckets.delete(client);
    }
  }

  get size(): number {
    return this.#buckets.size;
  }
}

/* ───────────────────────────────────────────────────────────── gateway ── */

export interface GatewayOptions {
  /** Forwards a call to the node. Injectable so tests need no node. */
  readonly call: (method: string, params: Record<string, unknown>) => Promise<unknown>;
  readonly port?: number;
  readonly host?: string;
  readonly faucet?: Faucet;
  /**
   * Origins allowed to call this from a browser. `'*'` is the honest default
   * for a public read-only testnet explorer: the data is public, there are no
   * credentials, and a wrong allowlist just breaks the site silently.
   */
  readonly cors?: string;
  readonly cache?: ResponseCache;
  readonly limiter?: RateLimiter;
  readonly now?: () => number;
  /** Requests per minute per client. */
  readonly ratePerMinute?: number;
}

export interface GatewayResponse {
  readonly status: number;
  readonly body: unknown;
  readonly cached?: boolean;
  readonly retryAfterSeconds?: number;
}

export class Gateway {
  readonly cache: ResponseCache;
  readonly limiter: RateLimiter;
  readonly faucet?: Faucet;
  readonly cors: string;
  readonly port: number;
  readonly host: string;
  readonly #call: GatewayOptions['call'];
  readonly #now: () => number;
  #server?: Server;
  #requests = 0;
  #refused = 0;

  constructor(opts: GatewayOptions) {
    this.#call = opts.call;
    this.port = opts.port ?? 8080;
    this.host = opts.host ?? '0.0.0.0';
    this.faucet = opts.faucet;
    this.cors = opts.cors ?? '*';
    this.cache = opts.cache ?? new ResponseCache();
    this.limiter = opts.limiter ?? new RateLimiter(60, opts.ratePerMinute ?? 60);
    this.#now = opts.now ?? Date.now;
  }

  /**
   * Handle one RPC call. Exposed without HTTP so the policy — allowlist,
   * cache, limits — can be tested directly.
   */
  async rpc(
    method: string,
    params: Record<string, unknown>,
    client: string,
  ): Promise<GatewayResponse> {
    const now = this.#now();
    this.#requests++;

    const ttl = Object.hasOwn(PUBLIC_METHODS, method) ? PUBLIC_METHODS[method] : undefined;
    if (ttl === undefined) {
      this.#refused++;
      return {
        status: 403,
        body: {
          error: {
            code: -32601,
            message: `'${method}' is not available through the public gateway`,
            available: Object.keys(PUBLIC_METHODS),
          },
        },
      };
    }

    /*
     * The cache is checked before the rate limiter on purpose. A cached answer
     * costs the node nothing, and refusing it would penalise the visitor whose
     * page load happens to arrive in a busy second while doing nothing to
     * protect the thing the limit exists to protect.
     */
    const key = ResponseCache.key(method, params);
    const hit = this.cache.get(key, now);
    if (hit !== undefined) return { status: 200, body: { result: hit }, cached: true };

    if (!this.limiter.take(client, now)) {
      this.#refused++;
      return {
        status: 429,
        body: { error: { code: -32000, message: 'rate limit exceeded — slow down' } },
        retryAfterSeconds: 5,
      };
    }

    try {
      const result = await this.#call(method, params);
      this.cache.set(key, result, ttl, now);
      return { status: 200, body: { result } };
    } catch (err) {
      /*
       * Errors are not cached. A transient node failure would otherwise be
       * served to everybody for the rest of the TTL, turning one bad second
       * into a minute of a broken explorer.
       */
      return { status: 200, body: { error: { code: -32603, message: (err as Error).message } } };
    }
  }

  stats() {
    return {
      requests: this.#requests,
      refused: this.#refused,
      cache: this.cache.stats,
      clients: this.limiter.size,
    };
  }

  /* ──────────────────────────────────────────────────────────── HTTP ── */

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => void this.#handle(req, res));
      server.on('error', reject);
      server.listen(this.port, this.host, () => {
        this.#server = server;
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.#server) return resolve();
      this.#server.close(() => resolve());
      this.#server = undefined;
    });
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'access-control-allow-origin': this.cors,
      'access-control-allow-headers': 'content-type',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
    };

    if (req.method === 'OPTIONS') {
      res.writeHead(204, headers);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', 'http://gateway');
    const client = clientKey(req.socket.remoteAddress ?? '');

    // Health, for the reverse proxy and for uptime checks.
    if (url.pathname === '/health') {
      res.writeHead(200, headers);
      res.end(JSON.stringify({ ok: true, ...this.stats() }));
      return;
    }

    if (url.pathname === '/faucet' && req.method === 'GET') {
      res.writeHead(this.faucet ? 200 : 404, headers);
      res.end(JSON.stringify(this.faucet ? this.faucet.info() : { error: 'no faucet configured' }));
      return;
    }

    let body: Record<string, unknown> = {};
    if (req.method === 'POST') {
      const raw = await readBody(req, 64 * 1024);
      if (raw === undefined) {
        res.writeHead(413, headers);
        res.end(JSON.stringify({ error: { message: 'body too large' } }));
        return;
      }
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        res.writeHead(400, headers);
        res.end(JSON.stringify({ error: { message: 'malformed JSON' } }));
        return;
      }
    }

    if (url.pathname === '/faucet' && req.method === 'POST') {
      if (!this.faucet) {
        res.writeHead(404, headers);
        res.end(JSON.stringify({ error: 'no faucet configured' }));
        return;
      }
      // A faucet request costs far more than a query, so it is priced higher
      // against the same bucket.
      if (!this.limiter.take(client, this.#now(), 10)) {
        res.writeHead(429, { ...headers, 'retry-after': '30' });
        res.end(JSON.stringify({ allowed: false, reason: 'rate limit exceeded' }));
        return;
      }
      const result = await this.faucet.request(String(body.address ?? ''), client);
      res.writeHead(result.allowed ? 200 : 429, headers);
      res.end(JSON.stringify(result, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)));
      return;
    }

    // Everything else is an RPC call. GET is supported for `?method=` so a
    // browser address bar and `curl` both work without ceremony.
    const method = String(body.method ?? url.searchParams.get('method') ?? '');
    const params =
      (body.params as Record<string, unknown>) ??
      Object.fromEntries([...url.searchParams].filter(([k]) => k !== 'method'));

    if (!method) {
      res.writeHead(400, headers);
      res.end(JSON.stringify({ error: { message: 'method is required' }, available: Object.keys(PUBLIC_METHODS) }));
      return;
    }

    const response = await this.rpc(method, coerce(params), client);
    if (response.retryAfterSeconds) headers['retry-after'] = String(response.retryAfterSeconds);
    if (response.cached) headers['x-cache'] = 'hit';
    res.writeHead(response.status, headers);
    res.end(JSON.stringify(response.body, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  }
}

/** Query-string values arrive as strings; height and verbose need real types. */
function coerce(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (typeof v !== 'string') {
      out[k] = v;
      continue;
    }
    if (v === 'true') out[k] = true;
    else if (v === 'false') out[k] = false;
    else if (/^\d+$/.test(v)) out[k] = Number(v);
    else out[k] = v;
  }
  return out;
}

async function readBody(req: IncomingMessage, max: number): Promise<string | undefined> {
  let size = 0;
  let body = '';
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > max) {
      req.destroy();
      return undefined;
    }
    body += (chunk as Buffer).toString('utf8');
  }
  return body;
}
