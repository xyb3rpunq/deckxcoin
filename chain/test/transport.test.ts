/**
 * Encrypted transport.
 *
 * Tested without a socket, on purpose. A transport bug that only shows up
 * through a live connection presents as "the peer handshakes and then never
 * speaks", which is among the least informative failure modes there is — and
 * is exactly how the 16-byte-IV bug in `lengthMask` first appeared.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  Cipher,
  deriveSessionKeys,
  Handshake,
  HANDSHAKE_BYTES,
  LENGTH_BYTES,
  REKEY_INTERVAL,
  TAG_BYTES,
} from '../src/net/transport.ts';
import { ecdh, equalBytes, fromHex, keyFromSeed, pointFromSecret, toHex, toXOnly, utf8 } from '../src/crypto.ts';
import { encodeMessage, decodeMessage, MSG } from '../src/net/wire.ts';
import { REGTEST, TESTNET } from '../src/params.ts';

/** Two handshakes that have exchanged greetings. */
function pair(seedA = 'transport/a', seedB = 'transport/b', network = REGTEST.name) {
  const a = new Handshake(network, keyFromSeed(seedA));
  const b = new Handshake(network, keyFromSeed(seedB));
  const forA = a.accept(b.greeting());
  const forB = b.accept(a.greeting());
  return { a, b, cipherA: forA.cipher, cipherB: forB.cipher };
}

/* ──────────────────────────────────────────────────────── handshake ── */

test('both sides derive the same session from opposite halves of the exchange', () => {
  const { cipherA, cipherB } = pair();
  assert.equal(cipherA.sessionId, cipherB.sessionId);
  assert.equal(fromHex(cipherA.sessionId).length, 32);
});

test('the greeting is a bare x-coordinate, with no parity byte to fingerprint', () => {
  const h = new Handshake(REGTEST.name, keyFromSeed('transport/greeting'));
  const greeting = h.greeting();

  assert.equal(greeting.length, HANDSHAKE_BYTES);
  assert.equal(HANDSHAKE_BYTES, 32);
  assert.equal(toHex(greeting), toHex(toXOnly(pointFromSecret(keyFromSeed('transport/greeting')))));

  /*
   * The point of dropping the parity byte: a compressed point always starts
   * 0x02 or 0x03, which hands a traffic classifier a free signal. Across many
   * greetings the first byte must now look like anything.
   */
  const firstBytes = new Set<number>();
  for (let i = 0; i < 60; i++) {
    firstBytes.add(new Handshake(REGTEST.name, keyFromSeed(`transport/spread/${i}`)).greeting()[0]);
  }
  assert.ok(firstBytes.size > 20, `first byte should vary widely, saw ${firstBytes.size} values`);
  assert.ok(
    [...firstBytes].some((b) => b !== 0x02 && b !== 0x03),
    'the greeting must not look like a compressed point',
  );
});

test('a peer echoing our own key is refused', () => {
  const h = new Handshake(REGTEST.name, keyFromSeed('transport/echo'));
  assert.throws(() => h.accept(h.greeting()), /echoed our own ephemeral key/);
});

test('a malformed greeting is refused', () => {
  const h = () => new Handshake(REGTEST.name, keyFromSeed('transport/malformed'));

  assert.throws(() => h().accept(new Uint8Array(10)), /expected 32 bytes/);
  assert.throws(() => h().accept(new Uint8Array(33)), /expected 32 bytes/);

  // 32 bytes that are not an x-coordinate on the curve. Roughly half of all
  // strings are not, so this is the common case for random garbage.
  const notOnCurve = new Uint8Array(32);
  assert.throws(() => h().accept(notOnCurve), /./, 'all-zero is not a valid point');

  const beyondField = new Uint8Array(32).fill(0xff);
  assert.throws(() => h().accept(beyondField), /./, 'a value past the field size is not a point');
});

test('the same handshake cannot be completed twice', () => {
  const a = new Handshake(REGTEST.name, keyFromSeed('transport/once/a'));
  const b = new Handshake(REGTEST.name, keyFromSeed('transport/once/b'));
  a.accept(b.greeting());
  assert.equal(a.complete, true);
  assert.throws(() => a.accept(b.greeting()), /already complete/);
});

test('sessions are bound to the network — same keys, different chain, different session', () => {
  const onRegtest = pair('transport/net/a', 'transport/net/b', REGTEST.name);
  const onTestnet = pair('transport/net/a', 'transport/net/b', TESTNET.name);
  assert.notEqual(
    onRegtest.cipherA.sessionId,
    onTestnet.cipherA.sessionId,
    'a testnet handshake must never derive mainnet keys',
  );
});

test('the two directions use different keys', () => {
  const secretA = keyFromSeed('transport/dir/a');
  const secretB = keyFromSeed('transport/dir/b');
  const pubA = pointFromSecret(secretA);
  const pubB = pointFromSecret(secretB);
  const shared = ecdh(secretA, pubB);

  const keysA = deriveSessionKeys(shared, REGTEST.name, pubA, pubB, true);
  const keysB = deriveSessionKeys(shared, REGTEST.name, pubA, pubB, false);

  assert.ok(equalBytes(keysA.send, keysB.recv), "A's send key is B's receive key");
  assert.ok(equalBytes(keysA.recv, keysB.send));
  assert.equal(equalBytes(keysA.send, keysA.recv), false, 'directions must not share a key');
  assert.equal(keysA.sessionId, keysB.sessionId);
});

/* ─────────────────────────────────────────────────────────── frames ── */

test('a frame round-trips', () => {
  const { cipherA, cipherB } = pair();
  const plaintext = encodeMessage(REGTEST.magic, MSG.PING, { nonce: 'abc' });

  const frame = cipherA.seal(plaintext);
  const opened = cipherB.open(frame);

  assert.equal(opened.error, undefined);
  assert.equal(opened.consumed, frame.length);
  assert.ok(equalBytes(opened.payload!, plaintext));
  assert.equal(decodeMessage(REGTEST.magic, opened.payload!).message!.command, MSG.PING);
});

test('the frame is longer than the plaintext by exactly the length prefix and tag', () => {
  const { cipherA } = pair();
  const plaintext = utf8('some payload');
  const frame = cipherA.seal(plaintext);
  assert.equal(frame.length, LENGTH_BYTES + plaintext.length + TAG_BYTES);
});

test('nothing recognisable survives encryption', () => {
  const { cipherA } = pair();
  const plaintext = encodeMessage(REGTEST.magic, MSG.TX, { secret: 'dxc1qsomeaddress' });
  const frame = cipherA.seal(plaintext);

  const asText = new TextDecoder('utf-8', { fatal: false }).decode(frame);
  assert.equal(asText.includes('dxc1qsomeaddress'), false, 'the address must not be readable');
  assert.equal(asText.includes(MSG.TX), false, 'the command name must not be readable');

  // The length prefix is masked, so the plaintext size is not sitting in the clear.
  const rawLength = (frame[0] << 16) | (frame[1] << 8) | frame[2];
  assert.notEqual(rawLength, plaintext.length, 'the length prefix must be encrypted');
});

test('a partial frame consumes nothing and waits', () => {
  const { cipherA, cipherB } = pair();
  const frame = cipherA.seal(utf8('waiting for the rest'));

  assert.equal(cipherB.open(frame.subarray(0, 2)).consumed, 0);
  assert.equal(cipherB.open(frame.subarray(0, frame.length - 1)).consumed, 0);
  assert.equal(cipherB.open(frame.subarray(0, 2)).error, undefined, 'incomplete is not an error');
});

test('two frames in one buffer decode in order', () => {
  const { cipherA, cipherB } = pair();
  const one = cipherA.seal(utf8('first'));
  const two = cipherA.seal(utf8('second'));
  const merged = new Uint8Array(one.length + two.length);
  merged.set(one, 0);
  merged.set(two, one.length);

  const a = cipherB.open(merged);
  assert.equal(new TextDecoder().decode(a.payload!), 'first');
  const b = cipherB.open(merged.subarray(a.consumed));
  assert.equal(new TextDecoder().decode(b.payload!), 'second');
});

/**
 * A frame the receiver is not expecting fails in one of three ways, and which
 * one is not worth pinning down:
 *
 *   • the masked length decrypts to something over the cap — an explicit error;
 *   • it decrypts to a plausible length and the AEAD tag rejects it — an error;
 *   • it decrypts to a length *longer than the buffer*, which is
 *     indistinguishable from "this frame has not fully arrived yet", so the
 *     reader waits.
 *
 * The third case is inherent: without the right key there is no way to tell a
 * truncated frame from a forged one. It is bounded — the announced length is
 * capped, and a peer that never sends the rest is dropped on the idle timeout.
 * BIP-324 has exactly the same property.
 *
 * The security claim is therefore the one asserted here: **no payload ever
 * emerges**. Not "an error is reported".
 */
function assertRejected(
  result: { payload?: Uint8Array; error?: string; consumed?: number },
  what: string,
): void {
  assert.equal(result.payload, undefined, `${what}: no payload may be produced`);
  assert.equal(result.consumed ?? 0, 0, `${what}: nothing may be consumed`);
}

test('frames must arrive in order — nonces are counters', () => {
  const { cipherA, cipherB } = pair();
  const one = cipherA.seal(utf8('first'));
  const two = cipherA.seal(utf8('second'));

  // Delivering the second frame first fails: its nonce does not match the
  // receiver's counter. That is the property that stops replay and reordering.
  assertRejected(cipherB.open(two), 'out-of-order frame');
  void one;
});

test('a replayed frame is rejected', () => {
  const { cipherA, cipherB } = pair();
  const frame = cipherA.seal(utf8('once'));

  assert.equal(cipherB.open(frame).error, undefined, 'the first delivery succeeds');
  assertRejected(cipherB.open(frame), 'replayed frame');
});

test('tampering with the ciphertext fails authentication', () => {
  const { cipherA, cipherB } = pair();
  const frame = cipherA.seal(utf8('do not modify me'));
  frame[LENGTH_BYTES + 2] ^= 0x01;
  assert.equal(cipherB.open(frame).error, 'frame failed authentication');
});

test('tampering with the encrypted length fails authentication', () => {
  const { cipherA, cipherB } = pair();
  const frame = cipherA.seal(utf8('length is authenticated too'));
  frame[1] ^= 0x01;
  const opened = cipherB.open(frame);
  // Either the announced length no longer matches, or the AAD check fails.
  assert.ok(opened.error !== undefined || opened.consumed === 0, 'a mangled length must not decode');
});

test('tampering with the tag fails authentication', () => {
  const { cipherA, cipherB } = pair();
  const frame = cipherA.seal(utf8('tagged'));
  frame[frame.length - 1] ^= 0xff;
  assert.equal(cipherB.open(frame).error, 'frame failed authentication');
});

test('a frame from a different session does not open', () => {
  const first = pair('transport/s1/a', 'transport/s1/b');
  const second = pair('transport/s2/a', 'transport/s2/b');
  const frame = first.cipherA.seal(utf8('for the first session only'));
  assertRejected(second.cipherB.open(frame), 'cross-session frame');
});

test('an oversized announced length is refused before allocating', () => {
  const { cipherB } = pair();
  // Craft a buffer whose masked length decodes to something enormous. Whatever
  // it decodes to, the receiver must not try to buffer 16 MiB on a peer's say-so.
  const hostile = new Uint8Array(LENGTH_BYTES + 8).fill(0xff);
  const opened = cipherB.open(hostile);
  assert.ok(opened.consumed === 0, 'nothing is consumed from a hostile frame');
});

test('the payload cap is enforced on send', () => {
  const { cipherA } = pair();
  assert.throws(() => cipherA.seal(new Uint8Array(9 * 1024 * 1024)), /exceeds the cap/);
});

/* ─────────────────────────────────────────────────────────── rekeying ── */

test('keys ratchet forward and both sides stay in step', () => {
  const { cipherA, cipherB } = pair();

  // Push past a rekey boundary. Both sides must ratchet at the same frame.
  for (let i = 0; i < REKEY_INTERVAL + 5; i++) {
    const frame = cipherA.seal(utf8(`frame ${i}`));
    const opened = cipherB.open(frame);
    assert.equal(opened.error, undefined, `frame ${i} failed after ${cipherA.framesSent} sends`);
    assert.equal(new TextDecoder().decode(opened.payload!), `frame ${i}`);
  }

  assert.equal(cipherA.framesSent, REKEY_INTERVAL + 5);
  assert.equal(cipherB.framesReceived, REKEY_INTERVAL + 5);
});

test('a cipher constructed from raw keys behaves identically', () => {
  const shared = ecdh(keyFromSeed('transport/raw/a'), pointFromSecret(keyFromSeed('transport/raw/b')));
  const pubA = pointFromSecret(keyFromSeed('transport/raw/a'));
  const pubB = pointFromSecret(keyFromSeed('transport/raw/b'));

  const send = new Cipher(deriveSessionKeys(shared, 'regtest', pubA, pubB, true));
  const recv = new Cipher(deriveSessionKeys(shared, 'regtest', pubA, pubB, false));

  const frame = send.seal(utf8('hello'));
  assert.equal(new TextDecoder().decode(recv.open(frame).payload!), 'hello');
});
