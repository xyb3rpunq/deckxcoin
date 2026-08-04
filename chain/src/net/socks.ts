/**
 * SOCKS5, so a node can reach the network through Tor.
 *
 * ── Why a blockchain node needs this ──────────────────────────────────────
 * The P2P layer here is already encrypted and identity-bound, so nobody on the
 * path can read what a node sends or impersonate its peers. None of that hides
 * *who is talking*. A node that dials out from its own address tells every peer
 * it connects to where it is, and a peer that receives a transaction first has
 * a good guess about who wrote it.
 *
 * That is not a theoretical concern: it is how chain-analysis firms cluster
 * addresses to people. Encryption protects the contents of a conversation; only
 * routing protects the fact that it happened.
 *
 * ── What this file is, and is not ─────────────────────────────────────────
 * It is a SOCKS5 client: enough of RFC 1928 to open a TCP connection through a
 * proxy, including the CONNECT-by-hostname form that `.onion` addresses need.
 *
 * It is **not** a Tor implementation. It speaks to a Tor daemon the operator
 * runs. Writing an onion router is a research project; using one correctly is
 * two hundred lines, and this is those.
 *
 * ── The part that is easy to get wrong ────────────────────────────────────
 * Resolving the hostname locally and connecting to the resulting IP defeats the
 * entire exercise — the DNS query leaks the destination in plaintext, from the
 * node's own address, to its own resolver. So the hostname is sent to the proxy
 * *as a hostname* (address type 0x03) and never resolved here. `dnsLeakCheck`
 * exists so a test can assert that.
 */

import { Socket } from 'node:net';

export const SOCKS5_VERSION = 0x05;

/** RFC 1928 authentication methods. Only "none" is offered. */
export const SOCKS5_AUTH = {
  NONE: 0x00,
  GSSAPI: 0x01,
  USERNAME: 0x02,
  NONE_ACCEPTABLE: 0xff,
} as const;

export const SOCKS5_CMD = { CONNECT: 0x01, BIND: 0x02, UDP: 0x03 } as const;

export const SOCKS5_ATYP = { IPV4: 0x01, DOMAIN: 0x03, IPV6: 0x04 } as const;

/** RFC 1928 reply codes, with what each one usually means in practice. */
export const SOCKS5_REPLY: Readonly<Record<number, string>> = {
  0x00: 'succeeded',
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable — for a .onion this usually means the service is down',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

export interface ProxyConfig {
  readonly host: string;
  readonly port: number;
  /** Tor's default SOCKS port. */
  readonly kind?: 'tor' | 'socks5';
}

export const TOR_DEFAULT_PROXY: ProxyConfig = { host: '127.0.0.1', port: 9050, kind: 'tor' };

/** True for a v3 onion address: 56 base-32 characters plus `.onion`. */
export function isOnion(host: string): boolean {
  return /^[a-z2-7]{56}\.onion$/i.test(host.trim());
}

/**
 * Would connecting to this host require a DNS lookup on this machine?
 *
 * The answer must be no for anything routed through Tor. A leaked lookup
 * announces the destination in plaintext, from the node's own address, before
 * a single encrypted byte is sent — and the connection that follows looks
 * perfectly private, which is what makes the mistake so durable.
 */
export function dnsLeakCheck(host: string, viaProxy: boolean): { leaks: boolean; reason: string } {
  const isIp = /^[\d.]+$/.test(host) || host.includes(':');
  if (isIp) return { leaks: false, reason: 'an address, not a name — nothing to resolve' };
  if (viaProxy) {
    return { leaks: false, reason: 'the name is sent to the proxy to resolve, not resolved here' };
  }
  return { leaks: true, reason: `'${host}' would be resolved locally, publishing it to the local resolver` };
}

/* ───────────────────────────────────────────────────────── handshake ── */

/** The greeting: version, one method, "no authentication". */
export function greeting(): Uint8Array {
  return Uint8Array.of(SOCKS5_VERSION, 1, SOCKS5_AUTH.NONE);
}

/**
 * The CONNECT request.
 *
 * Hostnames go out as hostnames. A `.onion` has no meaning outside Tor and
 * cannot be resolved at all, which makes the leak impossible to miss there —
 * but an ordinary hostname resolved locally leaks silently, so both take the
 * same path.
 */
export function connectRequest(host: string, port: number): Uint8Array {
  const trimmed = host.trim();

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    const octets = trimmed.split('.').map(Number);
    if (octets.some((o) => o < 0 || o > 255)) throw new Error(`socks5: bad IPv4 '${host}'`);
    return Uint8Array.of(
      SOCKS5_VERSION, SOCKS5_CMD.CONNECT, 0x00, SOCKS5_ATYP.IPV4,
      ...octets,
      (port >> 8) & 0xff, port & 0xff,
    );
  }

  const name = new TextEncoder().encode(trimmed);
  if (name.length === 0 || name.length > 255) throw new Error('socks5: hostname must be 1–255 bytes');
  return Uint8Array.of(
    SOCKS5_VERSION, SOCKS5_CMD.CONNECT, 0x00, SOCKS5_ATYP.DOMAIN,
    name.length, ...name,
    (port >> 8) & 0xff, port & 0xff,
  );
}

export interface HandshakeVerdict {
  readonly ok: boolean;
  readonly error?: string;
  /** Bytes consumed, so a caller can tell whether a reply is complete. */
  readonly consumed: number;
}

/** Parse the proxy's method selection. */
export function readMethodReply(data: Uint8Array): HandshakeVerdict {
  if (data.length < 2) return { ok: false, error: 'short method reply', consumed: 0 };
  if (data[0] !== SOCKS5_VERSION) return { ok: false, error: `not SOCKS5 (got version ${data[0]})`, consumed: 2 };
  if (data[1] === SOCKS5_AUTH.NONE_ACCEPTABLE) {
    return { ok: false, error: 'the proxy requires authentication and none was offered', consumed: 2 };
  }
  if (data[1] !== SOCKS5_AUTH.NONE) {
    return { ok: false, error: `the proxy chose method ${data[1]}, which is not supported`, consumed: 2 };
  }
  return { ok: true, consumed: 2 };
}

/**
 * Parse the CONNECT reply.
 *
 * Variable length: the bound address comes back in whichever form the proxy
 * chose, so the length depends on the address type. Reading a fixed ten bytes
 * works against Tor and then desynchronises against a proxy that answers with a
 * domain — a bug that looks like corruption much later.
 */
export function readConnectReply(data: Uint8Array): HandshakeVerdict {
  if (data.length < 5) return { ok: false, error: 'short connect reply', consumed: 0 };
  if (data[0] !== SOCKS5_VERSION) return { ok: false, error: `not SOCKS5 (got version ${data[0]})`, consumed: 0 };

  const status = data[1];
  const atyp = data[3];
  const addressLength =
    atyp === SOCKS5_ATYP.IPV4 ? 4 : atyp === SOCKS5_ATYP.IPV6 ? 16 : atyp === SOCKS5_ATYP.DOMAIN ? 1 + data[4] : -1;

  if (addressLength < 0) return { ok: false, error: `unknown address type ${atyp}`, consumed: 0 };
  const total = 4 + addressLength + 2;
  if (data.length < total) return { ok: false, error: 'incomplete connect reply', consumed: 0 };

  if (status !== 0x00) {
    return { ok: false, error: SOCKS5_REPLY[status] ?? `proxy refused with code ${status}`, consumed: total };
  }
  return { ok: true, consumed: total };
}

/* ────────────────────────────────────────────────────────── dialling ── */

export interface DialOptions {
  readonly proxy: ProxyConfig;
  readonly host: string;
  readonly port: number;
  readonly timeoutMs?: number;
}

/**
 * Open a TCP connection to `host:port` through a SOCKS5 proxy.
 *
 * Resolves to a connected socket, already past the handshake, which the caller
 * uses exactly as it would a direct one — the encrypted transport above does
 * not need to know it is talking through anything.
 */
export function dialThroughProxy(opts: DialOptions): Promise<Socket> {
  const timeoutMs = opts.timeoutMs ?? 30_000;

  return new Promise((resolve, reject) => {
    const socket = new Socket();
    let stage: 'greeting' | 'connect' | 'done' = 'greeting';
    let buffer = new Uint8Array(0);

    const fail = (message: string) => {
      socket.destroy();
      reject(new Error(`socks5: ${message}`));
    };

    // A Tor circuit takes seconds to build, and a proxy that accepts the TCP
    // connection and then says nothing would otherwise hang the dialler.
    const timer = setTimeout(() => fail(`timed out after ${timeoutMs}ms connecting to ${opts.host}`), timeoutMs);
    const done = () => clearTimeout(timer);

    socket.on('error', (err) => {
      done();
      fail(`${err.message} (proxy ${opts.proxy.host}:${opts.proxy.port})`);
    });

    socket.on('data', (chunk) => {
      const merged = new Uint8Array(buffer.length + chunk.length);
      merged.set(buffer);
      merged.set(chunk, buffer.length);
      buffer = merged;

      if (stage === 'greeting') {
        const verdict = readMethodReply(buffer);
        if (!verdict.consumed) return; // wait for more
        if (!verdict.ok) return done(), fail(verdict.error!);
        buffer = buffer.subarray(verdict.consumed);
        stage = 'connect';
        try {
          socket.write(connectRequest(opts.host, opts.port));
        } catch (err) {
          return done(), fail((err as Error).message);
        }
        if (buffer.length === 0) return;
      }

      if (stage === 'connect') {
        const verdict = readConnectReply(buffer);
        if (!verdict.consumed && !verdict.error?.includes('incomplete')) {
          if (verdict.error) return done(), fail(verdict.error);
        }
        if (!verdict.consumed) return; // wait for more
        if (!verdict.ok) return done(), fail(verdict.error!);

        buffer = buffer.subarray(verdict.consumed);
        stage = 'done';
        done();

        /*
         * Hand the socket over without losing bytes.
         *
         * The peer may have sent its first message in the same packet as the
         * proxy's reply. Removing the handshake's `data` listener does not stop
         * the stream — a socket that has been read from stays flowing — so
         * anything that arrives between here and the caller attaching its own
         * reader is simply dropped, and the connection appears to hang on the
         * first message.
         *
         * Pausing first makes the handover explicit: the leftovers go back on
         * the readable side, and the caller's own `data` listener resumes the
         * flow and receives them.
         */
        socket.pause();
        socket.removeAllListeners('data');
        if (buffer.length > 0) socket.unshift(Buffer.from(buffer));
        resolve(socket);

        /*
         * And resume, once the caller has had a chance to attach its reader.
         *
         * `pause()` is sticky: after an explicit pause, adding a `data`
         * listener does *not* put the stream back into flowing mode the way it
         * does on a fresh socket. Without this the handover looks perfect and
         * the first message never arrives — the connection simply hangs, which
         * is the least debuggable failure a transport can have.
         *
         * `setImmediate` rather than a microtask: the caller resumes from its
         * own `await` and may do a little work before subscribing.
         */
        setImmediate(() => socket.resume());
      }
    });

    socket.connect(opts.proxy.port, opts.proxy.host, () => {
      socket.write(greeting());
    });
  });
}

/**
 * Decide how to reach a peer.
 *
 * A `.onion` address has no meaning without a proxy — there is nothing to
 * connect to and no way to resolve it — so dialling one directly is refused
 * rather than attempted and reported as a network error.
 */
export function routeFor(
  host: string,
  proxy: ProxyConfig | undefined,
): { via: 'direct' | 'proxy'; error?: string } {
  if (isOnion(host)) {
    if (!proxy) {
      return {
        via: 'direct',
        error: `${host} is an onion address and no proxy is configured — start Tor and pass --proxy`,
      };
    }
    return { via: 'proxy' };
  }
  return { via: proxy ? 'proxy' : 'direct' };
}
