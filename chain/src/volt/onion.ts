/**
 * Volt — Sphinx onion routing.
 *
 * A routed payment must not tell the intermediate nodes who is paying whom.
 * Sphinx (Danezis–Goldberg, adopted by Lightning as BOLT-04) gives three
 * properties at once:
 *
 *   • per-hop confidentiality — hop *i* learns only its own instruction and
 *     the next hop's address; it cannot read anything beyond that;
 *   • constant packet size — the packet is the same 1366 bytes whether the
 *     route is one hop or twenty, so length reveals nothing about position;
 *   • integrity — each hop verifies an HMAC before forwarding, so a tampered
 *     packet fails at the first honest node rather than propagating.
 *
 * The construction here is BOLT-04's, with one substitution: the stream
 * cipher is SHA256 in counter mode instead of ChaCha20, because it keeps the
 * dependency surface to the one hash family the rest of the chain already
 * uses. The security argument is unchanged — both are PRFs keyed by the
 * per-hop shared secret.
 *
 * Fixed sizes:
 *   HOP_PAYLOAD 33 B  ‖  HMAC 32 B  →  HOP_SIZE 65 B
 *   MAX_HOPS 20        →  ROUTING_INFO 1300 B
 *   packet = version 1 + ephemeral 33 + routing 1300 + hmac 32 = 1366 B
 */

import {
  beBytes,
  beToBigInt,
  concat,
  ecdh,
  equalBytes,
  fromHex,
  pointFromSecret,
  pointMul,
  randomPrivateKey,
  scalarMul,
  sha256,
  taggedHash,
  toHex,
  utf8,
  type Hex,
} from '../crypto.ts';

export const HOP_PAYLOAD_SIZE = 33;
export const HMAC_SIZE = 32;
export const HOP_SIZE = HOP_PAYLOAD_SIZE + HMAC_SIZE; // 65
export const MAX_HOPS = 20;
export const ROUTING_INFO_SIZE = MAX_HOPS * HOP_SIZE; // 1300
export const PACKET_SIZE = 1 + 33 + ROUTING_INFO_SIZE + HMAC_SIZE; // 1366
export const ONION_VERSION = 0;

export interface HopPayload {
  /** Channel to forward over. Zero for the final hop. */
  readonly shortChannelId: bigint;
  /** Amount the next hop should receive, in zaps. */
  readonly amountToForward: bigint;
  /** CLTV expiry the outgoing HTLC must carry. */
  readonly outgoingCltv: number;
  /** Set on the final hop only. */
  readonly final: boolean;
}

export interface OnionPacket {
  readonly version: number;
  /** Compressed ephemeral point for this hop. Rotated at every forward. */
  readonly ephemeral: Hex;
  readonly routingInfo: Hex;
  readonly hmac: Hex;
}

/* ------------------------------------------------------------- primitives */

/** SHA256 counter-mode keystream. A PRF keyed by the per-hop shared secret. */
function keystream(key: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const block = sha256(concat(key, beBytes(BigInt(counter), 4)));
    out.set(block.subarray(0, Math.min(32, length - offset)), offset);
    offset += 32;
    counter += 1;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

const rhoKey = (ss: Uint8Array): Uint8Array => taggedHash('Volt/onion/rho', ss);
const muKey = (ss: Uint8Array): Uint8Array => taggedHash('Volt/onion/mu', ss);
const blindKey = (ephemeral: Uint8Array, ss: Uint8Array): bigint =>
  beToBigInt(taggedHash('Volt/onion/blind', ephemeral, ss));

function mac(key: Uint8Array, data: Uint8Array, assoc: Uint8Array): Uint8Array {
  return taggedHash('Volt/onion/hmac', key, data, assoc);
}

/* ------------------------------------------------------------ hop payloads */

export function encodeHopPayload(p: HopPayload): Uint8Array {
  return concat(
    Uint8Array.of(p.final ? 1 : 0),
    beBytes(p.shortChannelId, 8),
    beBytes(p.amountToForward, 8),
    beBytes(BigInt(p.outgoingCltv), 4),
    new Uint8Array(12), // reserved — keeps the payload at a fixed 33 bytes
  );
}

export function decodeHopPayload(b: Uint8Array): HopPayload {
  if (b.length !== HOP_PAYLOAD_SIZE) throw new Error('decodeHopPayload: wrong size');
  return {
    final: b[0] === 1,
    shortChannelId: beToBigInt(b.subarray(1, 9)),
    amountToForward: beToBigInt(b.subarray(9, 17)),
    outgoingCltv: Number(beToBigInt(b.subarray(17, 21))),
  };
}

/* ------------------------------------------------------- shared secrets */

/**
 * Derive one shared secret per hop, rotating the ephemeral key as we go.
 *
 * The rotation is what stops two colluding hops on the same route from
 * recognising that they are on the same route: each sees a different
 * ephemeral point, and linking them requires solving a discrete log.
 */
export function deriveSharedSecrets(
  sessionKey: Uint8Array,
  hopPubkeys: readonly Uint8Array[],
): { secrets: Uint8Array[]; ephemerals: Uint8Array[] } {
  const secrets: Uint8Array[] = [];
  const ephemerals: Uint8Array[] = [];

  let ephemeralPriv = sessionKey;
  let ephemeralPub = pointFromSecret(sessionKey);

  for (const hop of hopPubkeys) {
    const ss = ecdh(ephemeralPriv, hop);
    secrets.push(ss);
    ephemerals.push(ephemeralPub);

    const blind = blindKey(ephemeralPub, ss);
    ephemeralPriv = scalarMul(ephemeralPriv, blind);
    ephemeralPub = pointMul(ephemeralPub, blind);
  }
  return { secrets, ephemerals };
}

/* -------------------------------------------------------------- filler */

/**
 * Deterministic filler.
 *
 * Every hop shifts the routing block left and appends `HOP_SIZE` bytes of
 * keystream to the tail. Without a matching filler baked in by the sender,
 * that tail would be all-zero after decryption — instantly revealing how many
 * hops remain. The filler makes the tail indistinguishable from ciphertext at
 * every position in the route.
 */
function generateFiller(secrets: readonly Uint8Array[]): Uint8Array {
  const n = secrets.length;
  let filler = new Uint8Array(0);
  for (let i = 0; i < n - 1; i++) {
    const extended = new Uint8Array(filler.length + HOP_SIZE);
    extended.set(filler, 0);
    filler = extended;
    const stream = keystream(rhoKey(secrets[i]), ROUTING_INFO_SIZE + HOP_SIZE);
    const start = ROUTING_INFO_SIZE + HOP_SIZE - filler.length;
    filler = xor(filler, stream.subarray(start, ROUTING_INFO_SIZE + HOP_SIZE));
  }
  return filler;
}

/* ------------------------------------------------------------ construction */

export interface OnionBuild {
  readonly packet: OnionPacket;
  /** Shared secrets, kept by the sender so it can decrypt returned failures. */
  readonly sharedSecrets: Hex[];
}

/**
 * Build an onion for `hops`, innermost first in construction order but
 * supplied outermost-first by the caller (source → destination).
 *
 * `assocData` binds the onion to the payment hash. Without it, a hop could
 * lift the onion off one HTLC and attach it to another.
 */
export function buildOnion(
  hopPubkeys: readonly Hex[],
  payloads: readonly HopPayload[],
  assocData: Uint8Array,
  sessionKey: Uint8Array = randomPrivateKey(),
): OnionBuild {
  if (hopPubkeys.length !== payloads.length) throw new Error('buildOnion: hop/payload mismatch');
  if (hopPubkeys.length === 0) throw new Error('buildOnion: empty route');
  if (hopPubkeys.length > MAX_HOPS) throw new Error(`buildOnion: route exceeds ${MAX_HOPS} hops`);

  const pubs = hopPubkeys.map(fromHex);
  const { secrets, ephemerals } = deriveSharedSecrets(sessionKey, pubs);
  const filler = generateFiller(secrets);

  // Start from a pad derived from the session key: pseudorandom, not zeroes,
  // so an unused tail is never distinguishable from real ciphertext.
  let routingInfo = keystream(taggedHash('Volt/onion/pad', sessionKey), ROUTING_INFO_SIZE);
  let hmac = new Uint8Array(HMAC_SIZE);

  for (let i = hopPubkeys.length - 1; i >= 0; i--) {
    const ss = secrets[i];
    // Shift right by one hop, dropping the tail.
    const shifted = new Uint8Array(ROUTING_INFO_SIZE);
    shifted.set(encodeHopPayload(payloads[i]), 0);
    shifted.set(hmac, HOP_PAYLOAD_SIZE);
    shifted.set(routingInfo.subarray(0, ROUTING_INFO_SIZE - HOP_SIZE), HOP_SIZE);

    routingInfo = xor(shifted, keystream(rhoKey(ss), ROUTING_INFO_SIZE));

    if (i === hopPubkeys.length - 1 && filler.length > 0) {
      routingInfo.set(filler, ROUTING_INFO_SIZE - filler.length);
    }
    hmac = mac(muKey(ss), routingInfo, assocData);
  }

  return {
    packet: {
      version: ONION_VERSION,
      ephemeral: toHex(ephemerals[0]),
      routingInfo: toHex(routingInfo),
      hmac: toHex(hmac),
    },
    sharedSecrets: secrets.map(toHex),
  };
}

/* -------------------------------------------------------------- processing */

export interface OnionPeel {
  readonly payload: HopPayload;
  /** Packet to forward. Undefined when this hop is the final recipient. */
  readonly next?: OnionPacket;
  readonly sharedSecret: Hex;
}

/**
 * Peel one layer. Throws on a bad HMAC — a hop must not forward a packet it
 * cannot authenticate, or it becomes a free amplifier for garbage.
 */
export function peelOnion(
  packet: OnionPacket,
  nodePrivkey: Uint8Array,
  assocData: Uint8Array,
): OnionPeel {
  if (packet.version !== ONION_VERSION) throw new Error(`peelOnion: unsupported version ${packet.version}`);

  const ephemeral = fromHex(packet.ephemeral);
  const ss = ecdh(nodePrivkey, ephemeral);
  const routingInfo = fromHex(packet.routingInfo);
  if (routingInfo.length !== ROUTING_INFO_SIZE) throw new Error('peelOnion: bad routing info size');

  const expected = mac(muKey(ss), routingInfo, assocData);
  if (!equalBytes(expected, fromHex(packet.hmac))) {
    throw new Error('peelOnion: HMAC mismatch — packet was tampered with or is not for this node');
  }

  // Append a hop's worth of zeroes, then decrypt: the keystream regenerates
  // exactly the filler bytes the sender pre-computed.
  const padded = concat(routingInfo, new Uint8Array(HOP_SIZE));
  const decrypted = xor(padded, keystream(rhoKey(ss), ROUTING_INFO_SIZE + HOP_SIZE));

  const payload = decodeHopPayload(decrypted.subarray(0, HOP_PAYLOAD_SIZE));
  const nextHmac = decrypted.subarray(HOP_PAYLOAD_SIZE, HOP_SIZE);
  const nextRouting = decrypted.subarray(HOP_SIZE, HOP_SIZE + ROUTING_INFO_SIZE);

  if (payload.final) {
    return { payload, sharedSecret: toHex(ss) };
  }

  const blind = blindKey(ephemeral, ss);
  return {
    payload,
    sharedSecret: toHex(ss),
    next: {
      version: ONION_VERSION,
      ephemeral: toHex(pointMul(ephemeral, blind)),
      routingInfo: toHex(nextRouting),
      hmac: toHex(nextHmac),
    },
  };
}

/* ----------------------------------------------------------- failure paths */

/**
 * Onion-encrypt a failure message on the way back. Each hop adds a layer with
 * its own shared secret, so only the sender can read the innermost reason —
 * and the sender can tell *which* hop failed by counting how many layers it
 * had to strip.
 */
export function wrapFailure(reason: string, sharedSecret: Hex): Hex {
  const data = utf8(reason);
  const stream = keystream(rhoKey(fromHex(sharedSecret)), data.length);
  return toHex(xor(data, stream));
}

export function unwrapFailure(blob: Hex, sharedSecret: Hex): string {
  const data = fromHex(blob);
  const stream = keystream(rhoKey(fromHex(sharedSecret)), data.length);
  return new TextDecoder().decode(xor(data, stream));
}

export const packetSizeOf = (p: OnionPacket): number =>
  1 + fromHex(p.ephemeral).length + fromHex(p.routingInfo).length + fromHex(p.hmac).length;
