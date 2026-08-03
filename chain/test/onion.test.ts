/** Sphinx onion: confidentiality, constant size, integrity. */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildOnion,
  peelOnion,
  wrapFailure,
  unwrapFailure,
  MAX_HOPS,
  PACKET_SIZE,
  packetSizeOf,
  ROUTING_INFO_SIZE,
  type HopPayload,
} from '../src/volt/onion.ts';
import { fromHex, keyFromSeed, keyPairFromSeed, toHex, utf8 } from '../src/crypto.ts';

function route(names: string[]) {
  const keys = names.map((n) => keyPairFromSeed(`onion/${n}`));
  return { keys, pubkeys: keys.map((k) => toHex(k.publicKey)) };
}

function payloads(n: number): HopPayload[] {
  return Array.from({ length: n }, (_, i) => ({
    shortChannelId: i === n - 1 ? 0n : BigInt(1000 + i),
    amountToForward: BigInt(1_000_000 - i * 100),
    outgoingCltv: 900 - i * 40,
    final: i === n - 1,
  }));
}

test('a three-hop onion peels correctly at every hop', () => {
  const { keys, pubkeys } = route(['bob', 'carol', 'dave']);
  const hops = payloads(3);
  const assoc = utf8('payment-hash');

  const { packet } = buildOnion(pubkeys, hops, assoc, keyFromSeed('onion/session'));

  const atBob = peelOnion(packet, keys[0].privateKey, assoc);
  assert.equal(atBob.payload.final, false);
  assert.equal(atBob.payload.shortChannelId, hops[0].shortChannelId);
  assert.equal(atBob.payload.amountToForward, hops[0].amountToForward);
  assert.ok(atBob.next);

  const atCarol = peelOnion(atBob.next!, keys[1].privateKey, assoc);
  assert.equal(atCarol.payload.final, false);
  assert.equal(atCarol.payload.amountToForward, hops[1].amountToForward);
  assert.ok(atCarol.next);

  const atDave = peelOnion(atCarol.next!, keys[2].privateKey, assoc);
  assert.equal(atDave.payload.final, true);
  assert.equal(atDave.payload.amountToForward, hops[2].amountToForward);
  assert.equal(atDave.next, undefined);
});

test('packet size is constant regardless of route length', () => {
  const assoc = utf8('x');
  const sizes = new Set<number>();
  for (const n of [1, 2, 5, 12, MAX_HOPS]) {
    const names = Array.from({ length: n }, (_, i) => `hop${i}`);
    const { pubkeys } = route(names);
    const { packet } = buildOnion(pubkeys, payloads(n), assoc, keyFromSeed(`s/${n}`));
    sizes.add(packetSizeOf(packet));
    assert.equal(fromHex(packet.routingInfo).length, ROUTING_INFO_SIZE);
  }
  assert.equal(sizes.size, 1, `packet size leaked route length: ${[...sizes]}`);
  assert.equal([...sizes][0], PACKET_SIZE);
});

test('a hop cannot read a layer addressed to a different hop', () => {
  const { keys, pubkeys } = route(['bob', 'carol', 'dave']);
  const assoc = utf8('h');
  const { packet } = buildOnion(pubkeys, payloads(3), assoc, keyFromSeed('s'));

  // Carol receives the outermost packet, which is Bob's.
  assert.throws(() => peelOnion(packet, keys[1].privateKey, assoc), /HMAC mismatch/);
  // Dave likewise.
  assert.throws(() => peelOnion(packet, keys[2].privateKey, assoc), /HMAC mismatch/);
});

test('tampering with the routing block is detected', () => {
  const { keys, pubkeys } = route(['bob', 'carol']);
  const assoc = utf8('h');
  const { packet } = buildOnion(pubkeys, payloads(2), assoc, keyFromSeed('s'));

  const bytes = fromHex(packet.routingInfo);
  bytes[7] ^= 0xff;
  const tampered = { ...packet, routingInfo: toHex(bytes) };

  assert.throws(() => peelOnion(tampered, keys[0].privateKey, assoc), /HMAC mismatch/);
});

test('an onion is bound to its payment hash and cannot be re-attached', () => {
  const { keys, pubkeys } = route(['bob', 'carol']);
  const { packet } = buildOnion(pubkeys, payloads(2), utf8('hash-A'), keyFromSeed('s'));
  assert.throws(() => peelOnion(packet, keys[0].privateKey, utf8('hash-B')), /HMAC mismatch/);
});

test('ephemeral keys differ at every hop, so colluding hops cannot link the route', () => {
  const { keys, pubkeys } = route(['bob', 'carol', 'dave']);
  const assoc = utf8('h');
  const { packet } = buildOnion(pubkeys, payloads(3), assoc, keyFromSeed('s'));

  const e1 = packet.ephemeral;
  const p1 = peelOnion(packet, keys[0].privateKey, assoc);
  const e2 = p1.next!.ephemeral;
  const p2 = peelOnion(p1.next!, keys[1].privateKey, assoc);
  const e3 = p2.next!.ephemeral;

  assert.equal(new Set([e1, e2, e3]).size, 3);
});

test('routes longer than MAX_HOPS are refused rather than truncated', () => {
  const names = Array.from({ length: MAX_HOPS + 1 }, (_, i) => `h${i}`);
  const { pubkeys } = route(names);
  assert.throws(
    () => buildOnion(pubkeys, payloads(MAX_HOPS + 1), utf8('h')),
    /exceeds 20 hops/,
  );
});

test('failure messages round-trip through their shared secret', () => {
  const secret = toHex(keyFromSeed('failure/secret'));
  const blob = wrapFailure('temporary_channel_failure', secret);
  assert.notEqual(blob, '');
  assert.equal(unwrapFailure(blob, secret), 'temporary_channel_failure');
  const wrong = toHex(keyFromSeed('failure/other'));
  assert.notEqual(unwrapFailure(blob, wrong), 'temporary_channel_failure');
});
