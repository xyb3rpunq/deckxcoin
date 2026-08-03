/**
 * Node identity and man-in-the-middle detection.
 *
 * Encryption without identity binding stops a passive observer and nothing
 * else. The test that matters here is the last one: a relay that terminates
 * both sides — exactly what an active attacker does — must be caught.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Socket, type Server } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  authDigest,
  checkAuth,
  forgetIdentity,
  IDENTITY_VERDICT,
  identityFromSeed,
  isFatalVerdict,
  judgeIdentity,
  loadIdentity,
  parsePeerAddress,
  signAuth,
} from '../src/net/identity.ts';
import { ChainStore } from '../src/store/sqlite.ts';
import { fromHex, keyPairFromSeed, sign, toHex } from '../src/crypto.ts';
import { DeckxNode } from '../src/node/node.ts';
import { REGTEST } from '../src/params.ts';
import { Cipher, Handshake, HANDSHAKE_BYTES } from '../src/net/transport.ts';

const dirs: string[] = [];
const running: DeckxNode[] = [];
const servers: Server[] = [];
let nextPort = 29700;

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'deckx-id-'));
  dirs.push(dir);
  return dir;
}

function tempStore(): ChainStore {
  return new ChainStore(join(tempDir(), 'chain.sqlite'));
}

async function spawnNode(opts: { connect?: string[]; seed?: string } = {}): Promise<DeckxNode> {
  const node = new DeckxNode({
    params: REGTEST,
    datadir: tempDir(),
    listenPort: nextPort++,
    listenHost: '127.0.0.1',
    connect: opts.connect,
    dialIntervalMs: 250,
    userAgent: 'deckxd-id-test',
    identity: opts.seed ? identityFromSeed(opts.seed) : undefined,
  });
  await node.start();
  running.push(node);
  return node;
}

async function until(check: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for: ${what}`);
}

test.after(async () => {
  for (const node of running) {
    try {
      await node.stop();
    } catch {
      /* already stopped */
    }
  }
  for (const server of servers) server.close();
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* Windows may still hold the WAL */
    }
  }
});

/* ─────────────────────────────────────────────────── auth primitives ── */

test('an auth proof verifies for its own session and no other', () => {
  const identity = identityFromSeed('id/auth');
  const sessionA = toHex(new Uint8Array(32).fill(1));
  const sessionB = toHex(new Uint8Array(32).fill(2));

  const proof = signAuth(identity, 'regtest', sessionA);
  assert.equal(checkAuth(proof, 'regtest', sessionA).ok, true);

  // The whole point: the same proof is worthless on a different session.
  const elsewhere = checkAuth(proof, 'regtest', sessionB);
  assert.equal(elsewhere.ok, false);
  assert.match(elsewhere.error!, /relay is sitting in the middle/);
});

test('an auth proof is bound to the network', () => {
  const identity = identityFromSeed('id/network');
  const session = toHex(new Uint8Array(32).fill(7));
  const proof = signAuth(identity, 'testnet', session);
  assert.equal(checkAuth(proof, 'testnet', session).ok, true);
  assert.equal(checkAuth(proof, 'mainnet', session).ok, false);
});

test('malformed auth payloads are refused rather than throwing', () => {
  const session = toHex(new Uint8Array(32).fill(3));
  assert.match(checkAuth(undefined, 'regtest', session).error!, /no identity proof/);
  assert.match(checkAuth({} as never, 'regtest', session).error!, /no identity proof/);
  assert.match(
    checkAuth({ identity: 'zz', signature: '00' }, 'regtest', session).error!,
    /not hex/,
  );
  assert.match(
    checkAuth({ identity: 'ab'.repeat(20), signature: '00'.repeat(64) }, 'regtest', session).error!,
    /must be 32 bytes/,
  );
});

test('a proof signed by one key cannot be presented under another identity', () => {
  const real = identityFromSeed('id/real');
  const impostor = identityFromSeed('id/impostor');
  const session = toHex(new Uint8Array(32).fill(9));

  const proof = signAuth(real, 'regtest', session);
  const stolen = { identity: toHex(impostor.publicKey), signature: proof.signature };
  assert.equal(checkAuth(stolen, 'regtest', session).ok, false);
});

test('the digest actually covers both the network and the session', () => {
  const s1 = toHex(new Uint8Array(32).fill(1));
  const s2 = toHex(new Uint8Array(32).fill(2));
  assert.notEqual(toHex(authDigest('regtest', s1)), toHex(authDigest('regtest', s2)));
  assert.notEqual(toHex(authDigest('regtest', s1)), toHex(authDigest('testnet', s1)));

  // And a hand-rolled signature over that digest verifies, so nothing else is mixed in.
  const key = keyPairFromSeed('id/digest');
  const manual = sign(authDigest('regtest', s1), key.privateKey);
  assert.equal(checkAuth({ identity: toHex(key.publicKey), signature: manual }, 'regtest', s1).ok, true);
});

/* ──────────────────────────────────────────────────── persistent key ── */

test('an identity is generated once and reloaded thereafter', () => {
  const path = join(tempDir(), 'identity');
  const first = loadIdentity(path);
  const second = loadIdentity(path);

  assert.equal(toHex(first.publicKey), toHex(second.publicKey));
  assert.equal(readFileSync(path, 'utf8').trim(), toHex(first.privateKey));
  assert.equal(fromHex(readFileSync(path, 'utf8').trim()).length, 32);
});

test('a corrupt identity file is replaced rather than crashing the node', () => {
  const path = join(tempDir(), 'identity');
  writeFileSync(path, 'not a key at all');
  const key = loadIdentity(path);
  assert.equal(key.publicKey.length, 32);
  assert.equal(readFileSync(path, 'utf8').trim(), toHex(key.privateKey));
});

/* ────────────────────────────────────────────────── address pinning ── */

test('peer addresses parse with and without a pinned identity', () => {
  assert.deepEqual(parsePeerAddress('127.0.0.1:1234', 9333), {
    host: '127.0.0.1',
    port: 1234,
    identity: undefined,
  });
  assert.deepEqual(parsePeerAddress('example.org', 9333), {
    host: 'example.org',
    port: 9333,
    identity: undefined,
  });

  const pin = 'ab'.repeat(32);
  assert.deepEqual(parsePeerAddress(`10.0.0.5:19333#${pin}`, 9333), {
    host: '10.0.0.5',
    port: 19333,
    identity: pin,
  });
  assert.throws(() => parsePeerAddress('10.0.0.5:1#nothex', 9333), /64 hex characters/);
});

/* ────────────────────────────────────────────── trust on first use ── */

test('TOFU: the first identity is learned, a repeat is known, a change is fatal', () => {
  const store = tempStore();
  const first = toHex(identityFromSeed('tofu/first').publicKey);
  const second = toHex(identityFromSeed('tofu/second').publicKey);

  const learned = judgeIdentity(store, '10.0.0.1', 9333, first);
  assert.equal(learned.verdict, IDENTITY_VERDICT.NEW);
  assert.equal(isFatalVerdict(learned.verdict), false);

  const again = judgeIdentity(store, '10.0.0.1', 9333, first);
  assert.equal(again.verdict, IDENTITY_VERDICT.KNOWN);
  assert.equal(isFatalVerdict(again.verdict), false);

  const changed = judgeIdentity(store, '10.0.0.1', 9333, second);
  assert.equal(changed.verdict, IDENTITY_VERDICT.CHANGED);
  assert.equal(changed.previous, first);
  assert.equal(isFatalVerdict(changed.verdict), true, 'a changed identity must abort');

  // A different address is judged independently.
  assert.equal(judgeIdentity(store, '10.0.0.2', 9333, second).verdict, IDENTITY_VERDICT.NEW);

  // Forgetting lets the node re-learn, which is the operator's escape hatch.
  forgetIdentity(store, '10.0.0.1', 9333);
  assert.equal(judgeIdentity(store, '10.0.0.1', 9333, second).verdict, IDENTITY_VERDICT.NEW);
  store.close();
});

test('a pinned identity overrides trust on first use, both ways', () => {
  const store = tempStore();
  const expected = toHex(identityFromSeed('pin/expected').publicKey);
  const other = toHex(identityFromSeed('pin/other').publicKey);

  const good = judgeIdentity(store, '10.0.0.9', 1, expected, expected);
  assert.equal(good.verdict, IDENTITY_VERDICT.PINNED);
  assert.equal(isFatalVerdict(good.verdict), false);

  const bad = judgeIdentity(store, '10.0.0.9', 1, other, expected);
  assert.equal(bad.verdict, IDENTITY_VERDICT.MISMATCH);
  assert.equal(isFatalVerdict(bad.verdict), true);
  store.close();
});

/* ───────────────────────────────────────────────── live connections ── */

test('two nodes prove their identities to each other', async () => {
  const a = await spawnNode({ seed: 'live/a' });
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`], seed: 'live/b' });
  await until(() => a.net.readyPeers.length === 1 && b.net.readyPeers.length === 1, 'handshake');

  const [peerOfB] = b.net.readyPeers;
  const [peerOfA] = a.net.readyPeers;

  assert.equal(peerOfB.peerIdentity, toHex(a.identity.publicKey));
  assert.equal(peerOfA.peerIdentity, toHex(b.identity.publicKey));
  assert.equal(peerOfB.info().identity.length, 64);
});

test('a correct pin is accepted', async () => {
  const a = await spawnNode({ seed: 'pin/live/a' });
  const pinned = toHex(a.identity.publicKey);
  const b = await spawnNode({
    connect: [`127.0.0.1:${a.net.listenPort}#${pinned}`],
    seed: 'pin/live/b',
  });

  await until(() => b.net.readyPeers.length === 1, 'pinned connection completes');
  assert.equal(b.net.readyPeers[0].peerIdentity, pinned);
});

test('a wrong pin refuses the connection', async () => {
  const a = await spawnNode({ seed: 'pin/wrong/a' });
  const wrong = toHex(identityFromSeed('pin/wrong/nobody').publicKey);

  const b = await spawnNode({ seed: 'pin/wrong/b' });
  const peer = await b.net.connect('127.0.0.1', a.net.listenPort, wrong);

  assert.equal(peer, undefined, 'the dial must not resolve to a ready peer');
  assert.equal(b.net.readyPeers.length, 0, 'no session may survive a pin mismatch');
});

/* ───────────────────────────────────────── the attack this prevents ── */

/**
 * A real man-in-the-middle.
 *
 * Note what this is *not*: a TCP proxy that shovels bytes. That would leave
 * Alice and Bob performing ECDH directly with each other, which is harmless
 * and proves nothing. A genuine attacker **terminates the cryptography on both
 * legs** — its own key exchange with Alice, a separate one with Bob — and
 * therefore sees plaintext in the middle.
 *
 * `observed` collects the decrypted frames, so the test can assert the attack
 * really did work at the transport layer before identity binding caught it.
 */
function startMitm(
  targetPort: number,
  listenPort: number,
  observed: string[],
): Promise<Server> {
  const server = createServer((fromVictim) => {
    const toTarget = new Socket();

    const victimSide = new Handshake(REGTEST.name);
    const targetSide = new Handshake(REGTEST.name);
    let victimCipher: Cipher | undefined;
    let targetCipher: Cipher | undefined;
    let victimBuf = new Uint8Array(0);
    let targetBuf = new Uint8Array(0);

    const drop = () => {
      fromVictim.destroy();
      toTarget.destroy();
    };
    fromVictim.on('error', drop);
    toTarget.on('error', drop);

    const append = (buf: Uint8Array, chunk: Buffer): Uint8Array => {
      const out = new Uint8Array(buf.length + chunk.length);
      out.set(buf, 0);
      out.set(chunk, buf.length);
      return out;
    };

    // Leg 1: pretend to be a node, to the victim.
    fromVictim.write(victimSide.greeting());
    fromVictim.on('data', (chunk) => {
      victimBuf = append(victimBuf, chunk);
      if (!victimCipher) {
        if (victimBuf.length < HANDSHAKE_BYTES) return;
        victimCipher = victimSide.accept(victimBuf.subarray(0, HANDSHAKE_BYTES)).cipher;
        victimBuf = victimBuf.subarray(HANDSHAKE_BYTES);
      }
      for (;;) {
        const opened = victimCipher.open(victimBuf);
        if (opened.consumed === 0 || !opened.payload) return;
        victimBuf = victimBuf.subarray(opened.consumed);
        // The attacker reads the plaintext — this is what encryption alone
        // fails to prevent — and forwards it verbatim onto the other leg.
        observed.push(new TextDecoder().decode(opened.payload).replace(/[^\x20-\x7e]/g, ''));
        if (targetCipher) toTarget.write(targetCipher.seal(opened.payload));
      }
    });

    // Leg 2: pretend to be the victim, to the real target.
    toTarget.connect(targetPort, '127.0.0.1', () => {
      toTarget.write(targetSide.greeting());
    });
    toTarget.on('data', (chunk) => {
      targetBuf = append(targetBuf, chunk);
      if (!targetCipher) {
        if (targetBuf.length < HANDSHAKE_BYTES) return;
        targetCipher = targetSide.accept(targetBuf.subarray(0, HANDSHAKE_BYTES)).cipher;
        targetBuf = targetBuf.subarray(HANDSHAKE_BYTES);
      }
      for (;;) {
        const opened = targetCipher.open(targetBuf);
        if (opened.consumed === 0 || !opened.payload) return;
        targetBuf = targetBuf.subarray(opened.consumed);
        observed.push(new TextDecoder().decode(opened.payload).replace(/[^\x20-\x7e]/g, ''));
        if (victimCipher) fromVictim.write(victimCipher.seal(opened.payload));
      }
    });
  });

  servers.push(server);
  return new Promise((resolve) => server.listen(listenPort, '127.0.0.1', () => resolve(server)));
}

test('MITM: an attacker terminating both legs reads plaintext but cannot authenticate', async () => {
  const alice = await spawnNode({ seed: 'mitm/alice' });
  const bob = await spawnNode({ seed: 'mitm/bob' });

  const observed: string[] = [];
  await startMitm(bob.net.listenPort, nextPort++, observed);
  const mitmPort = nextPort - 1;

  const peer = await alice.net.connect('127.0.0.1', mitmPort);

  /*
   * The attack genuinely succeeded at the transport layer: the attacker
   * decrypted real protocol messages. Encryption alone would have stopped
   * here, none the wiser.
   */
  assert.ok(observed.length > 0, 'the attacker must have decrypted at least one frame');
  assert.ok(
    observed.some((frame) => frame.includes('version')),
    `the attacker should have read a version message; saw ${observed.length} frames`,
  );

  // And it was caught anyway, because the identity proof is bound to a session
  // the attacker does not share with either side.
  assert.equal(peer, undefined, 'a man-in-the-middle must never reach ready');
  assert.equal(alice.net.readyPeers.length, 0, 'alice must hold no session through the attacker');

  // Alice can still reach Bob directly — the refusal was specific to the relay.
  const direct = await alice.net.connect('127.0.0.1', bob.net.listenPort);
  assert.ok(direct, 'a direct connection must still work');
  assert.equal(direct!.peerIdentity, toHex(bob.identity.publicKey));
});

test('a node reports its own identity through getinfo', async () => {
  const node = await spawnNode({ seed: 'info/identity' });
  const info = node.info() as { identity: string };
  assert.equal(info.identity, toHex(node.identity.publicKey));
  assert.equal(info.identity.length, 64);
});
