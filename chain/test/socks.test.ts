/**
 * SOCKS5, and running a node over Tor.
 *
 * The transport is already encrypted and identity-bound, so nobody on the path
 * can read a node's traffic or impersonate its peers. None of that hides *who
 * is talking*, and a node that dials from its own address tells every peer
 * where it is. Encryption protects the contents of a conversation; only routing
 * protects the fact that it happened.
 *
 * The test that matters most here is the DNS one. A node that resolves a
 * hostname locally and then connects to the resulting IP through Tor has
 * announced its destination in plaintext before sending an encrypted byte — and
 * the connection that follows looks perfectly private, which is exactly what
 * makes the mistake survive review.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server, type Socket } from 'node:net';

import {
  SOCKS5_ATYP,
  SOCKS5_AUTH,
  SOCKS5_CMD,
  SOCKS5_VERSION,
  TOR_DEFAULT_PROXY,
  connectRequest,
  dialThroughProxy,
  dnsLeakCheck,
  greeting,
  isOnion,
  readConnectReply,
  readMethodReply,
  routeFor,
} from '../src/net/socks.ts';

const ONION = 'deckxcoinnodeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion';

/* ──────────────────────────────────────────────────── onion addresses ── */

test('a v3 onion address is recognised, and a v2 one is not', () => {
  assert.equal(ONION.length - '.onion'.length, 56, 'harness check: v3 is 56 characters');
  assert.equal(isOnion(ONION), true);
  assert.equal(isOnion(ONION.toUpperCase()), true, 'onion addresses are case-insensitive');

  // v2 was 16 characters and was retired in 2021 — it must not be accepted.
  assert.equal(isOnion('expyuzz4wqqyqhjn.onion'), false);
  assert.equal(isOnion('example.org'), false);
  assert.equal(isOnion('127.0.0.1'), false);
});

test('dialling an onion address without a proxy is refused, not attempted', () => {
  /*
   * There is nothing to connect to: an onion address is not resolvable and
   * names no IP. Attempting it produces a generic network error much later,
   * which sends the operator looking at their firewall.
   */
  const without = routeFor(ONION, undefined);
  assert.equal(without.error !== undefined, true);
  assert.match(without.error!, /start Tor and pass --proxy/);

  const withProxy = routeFor(ONION, TOR_DEFAULT_PROXY);
  assert.equal(withProxy.via, 'proxy');
  assert.equal(withProxy.error, undefined);
});

test('an ordinary host goes direct without a proxy and through one with it', () => {
  assert.equal(routeFor('seed1.example.org', undefined).via, 'direct');
  assert.equal(routeFor('seed1.example.org', TOR_DEFAULT_PROXY).via, 'proxy');
});

/* ─────────────────────────────────────────────────────── the DNS leak ── */

test('a hostname is handed to the proxy, never resolved locally', () => {
  /*
   * The failure that undoes the whole exercise. Resolving locally publishes the
   * destination to the local resolver — in plaintext, from the node's own
   * address — before Tor is involved at all.
   */
  const leaked = dnsLeakCheck('seed1.example.org', false);
  assert.equal(leaked.leaks, true);
  assert.match(leaked.reason, /resolved locally/);

  const safe = dnsLeakCheck('seed1.example.org', true);
  assert.equal(safe.leaks, false);
  assert.match(safe.reason, /sent to the proxy to resolve/);

  // An address needs no lookup either way.
  assert.equal(dnsLeakCheck('203.0.113.5', false).leaks, false);
});

test('the CONNECT request carries the name as a name', () => {
  const request = connectRequest(ONION, 19333);

  assert.equal(request[0], SOCKS5_VERSION);
  assert.equal(request[1], SOCKS5_CMD.CONNECT);
  assert.equal(request[3], SOCKS5_ATYP.DOMAIN, 'must be the DOMAIN form, not a resolved address');
  assert.equal(request[4], ONION.length);

  const name = new TextDecoder().decode(request.subarray(5, 5 + ONION.length));
  assert.equal(name, ONION, 'the onion address itself must be on the wire');

  const port = (request[request.length - 2] << 8) | request[request.length - 1];
  assert.equal(port, 19333);
});

test('a literal IPv4 uses the address form', () => {
  const request = connectRequest('203.0.113.5', 8080);
  assert.equal(request[3], SOCKS5_ATYP.IPV4);
  assert.deepEqual([...request.subarray(4, 8)], [203, 0, 113, 5]);
  assert.equal((request[8] << 8) | request[9], 8080);
});

test('a malformed address is refused before anything is sent', () => {
  assert.throws(() => connectRequest('300.1.1.1', 80), /bad IPv4/);
  assert.throws(() => connectRequest('', 80), /1–255 bytes/);
  assert.throws(() => connectRequest('a'.repeat(256), 80), /1–255 bytes/);
});

/* ───────────────────────────────────────────────────────── handshake ── */

test('the greeting offers exactly one method: none', () => {
  // Offering username/password would invite a proxy to ask for credentials
  // this node does not have, and the failure would arrive as a refused peer.
  assert.deepEqual([...greeting()], [SOCKS5_VERSION, 1, SOCKS5_AUTH.NONE]);
});

test('a proxy demanding authentication is reported as such', () => {
  const reply = readMethodReply(Uint8Array.of(SOCKS5_VERSION, SOCKS5_AUTH.NONE_ACCEPTABLE));
  assert.equal(reply.ok, false);
  assert.match(reply.error!, /requires authentication/);
});

test('something that is not a SOCKS5 proxy is reported as such', () => {
  // Pointing --proxy at an HTTP proxy by mistake is common, and the first byte
  // is enough to say so.
  const reply = readMethodReply(Uint8Array.of(0x04, 0x00));
  assert.equal(reply.ok, false);
  assert.match(reply.error!, /not SOCKS5/);
});

test('the connect reply is read by its actual length, not a fixed ten bytes', () => {
  /*
   * The reply's bound address comes back in whichever form the proxy chose. A
   * reader that assumes IPv4 works against Tor and then desynchronises against
   * a proxy that answers with a domain — and the resulting corruption surfaces
   * much later, in the encrypted stream, looking like a framing bug.
   */
  const ipv4 = Uint8Array.of(SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP.IPV4, 127, 0, 0, 1, 0x00, 0x50);
  assert.deepEqual(readConnectReply(ipv4), { ok: true, consumed: 10 });

  const domain = Uint8Array.of(
    SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP.DOMAIN,
    5, 0x68, 0x6f, 0x73, 0x74, 0x73, // "hosts"
    0x00, 0x50,
  );
  assert.deepEqual(readConnectReply(domain), { ok: true, consumed: 12 });

  const ipv6 = Uint8Array.of(SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP.IPV6, ...new Array(16).fill(0), 0x00, 0x50);
  assert.deepEqual(readConnectReply(ipv6), { ok: true, consumed: 22 });
});

test('a partial reply asks for more rather than guessing', () => {
  const partial = Uint8Array.of(SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP.DOMAIN, 5, 0x68);
  const verdict = readConnectReply(partial);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.consumed, 0, 'nothing may be consumed from an incomplete reply');
});

test('a refusal explains itself in terms an operator can act on', () => {
  const unreachable = readConnectReply(
    Uint8Array.of(SOCKS5_VERSION, 0x04, 0x00, SOCKS5_ATYP.IPV4, 0, 0, 0, 0, 0, 0),
  );
  assert.equal(unreachable.ok, false);
  assert.match(unreachable.error!, /the service is down/);

  const refused = readConnectReply(
    Uint8Array.of(SOCKS5_VERSION, 0x05, 0x00, SOCKS5_ATYP.IPV4, 0, 0, 0, 0, 0, 0),
  );
  assert.match(refused.error!, /connection refused/);
});

/* ──────────────────────────────────────────── against a real proxy ── */

/** A SOCKS5 proxy that speaks the protocol and then echoes. */
function fakeProxy(): Promise<{
  server: Server;
  port: number;
  seen: { host: string; port: number }[];
  shutdown: () => void;
}> {
  const seen: { host: string; port: number }[] = [];
  const open: Socket[] = [];

  return new Promise((resolve) => {
    const server = createServer((socket: Socket) => {
      open.push(socket);
      let stage = 0;
      socket.on('data', (chunk) => {
        if (stage === 0) {
          socket.write(Uint8Array.from([SOCKS5_VERSION, SOCKS5_AUTH.NONE]));
          stage = 1;
          return;
        }
        if (stage === 1) {
          const atyp = chunk[3];
          if (atyp === SOCKS5_ATYP.DOMAIN) {
            const length = chunk[4];
            seen.push({
              host: new TextDecoder().decode(chunk.subarray(5, 5 + length)),
              port: (chunk[5 + length] << 8) | chunk[6 + length],
            });
          } else {
            seen.push({ host: [...chunk.subarray(4, 8)].join('.'), port: (chunk[8] << 8) | chunk[9] });
          }
          socket.write(
            Uint8Array.from([SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP.IPV4, 0, 0, 0, 0, 0, 0]),
          );
          stage = 2;
          // Whatever the far end would have sent first.
          socket.write(Buffer.from('HELLO'));
          return;
        }
        socket.write(chunk);
      });
      socket.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => {
      resolve({
        server,
        port: (server.address() as { port: number }).port,
        seen,
        shutdown: () => {
          for (const s of open) s.destroy();
          server.close();
        },
      });
    });
  });
}

test('a connection is opened through a proxy, and the onion name reaches it intact', async () => {
  const { port, seen, shutdown } = await fakeProxy();
  try {
    const socket = await dialThroughProxy({
      proxy: { host: '127.0.0.1', port },
      host: ONION,
      port: 19333,
      timeoutMs: 5000,
    });

    assert.deepEqual(seen, [{ host: ONION, port: 19333 }], 'the proxy must have been asked for the name');

    // Bytes the peer sent between the handshake ending and the caller
    // attaching a reader must not be lost.
    const first = await new Promise<string>((resolve) => socket.once('data', (d) => resolve(d.toString())));
    assert.equal(first, 'HELLO');

    socket.destroy();
  } finally {
    shutdown();
  }
});

test('a proxy that accepts and then goes silent times out', async () => {
  // A Tor circuit takes seconds to build; one that never does would otherwise
  // hang the dialler forever.
  const stuck: Socket[] = [];
  const server = createServer((socket) => {
    // Accept, say nothing — and keep a handle so the test can let go of it.
    stuck.push(socket);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;

  try {
    await assert.rejects(
      dialThroughProxy({ proxy: { host: '127.0.0.1', port }, host: ONION, port: 19333, timeoutMs: 300 }),
      /timed out/,
    );
  } finally {
    for (const s of stuck) s.destroy();
    server.close();
  }
});

test('the default proxy is Tor’s', () => {
  assert.equal(TOR_DEFAULT_PROXY.host, '127.0.0.1');
  assert.equal(TOR_DEFAULT_PROXY.port, 9050);
});
