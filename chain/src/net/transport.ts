/**
 * Encrypted transport.
 *
 * Every byte between two nodes is encrypted and authenticated. Before this
 * existed, frames were plaintext JSON: anyone on the path — a coffee-shop
 * router, an ISP, a hosting provider — could read which transactions
 * originated at which node, which is a deanonymisation oracle handed out for
 * free. Bitcoin closed the same hole with BIP-324 in 2023.
 *
 * ── Construction ──────────────────────────────────────────────────────────
 *
 *   1. Each side generates an **ephemeral** keypair and sends its 33-byte
 *      compressed point in the clear. Ephemeral means a compromised node key
 *      cannot decrypt yesterday's traffic: forward secrecy.
 *   2. `ss = ECDH(mine, theirs)`, then HKDF-SHA256 expands it into four keys —
 *      one AEAD key and one length-cipher key per direction — plus a session
 *      id. The salt binds the derivation to the network, so a testnet
 *      handshake can never produce mainnet keys.
 *   3. Directions are separated by sorting the two ephemeral keys, so both
 *      ends agree on who is "A" without a role negotiation.
 *   4. Every frame is `encrypted_length(3) ‖ ChaCha20-Poly1305(payload)`.
 *
 * ── Why the length is encrypted too ───────────────────────────────────────
 * A plaintext length field reveals message boundaries, and message sizes are a
 * fingerprint: a 1366-byte payload is an onion, a 24-byte one is a `verack`.
 * The length is therefore encrypted with a separate ChaCha20 keystream and
 * covered by the payload's AEAD tag as associated data, so it cannot be
 * tampered with either. This is BIP-324's design.
 *
 * ── Identity binding stops an active man-in-the-middle ────────────────────
 * Encryption alone only defeats a *passive* observer. An attacker who can
 * intercept and relay runs two separate sessions — one with each side — and
 * reads everything. Nothing in the ECDH above prevents that, because neither
 * ephemeral key is tied to anyone in particular.
 *
 * The fix is to sign the transcript. Each side proves ownership of a long-term
 * identity key over `sessionId`, which is derived from both ephemeral keys. A
 * relaying attacker necessarily has *different* session ids on its two legs,
 * so a signature it received on one leg is worthless on the other, and it
 * cannot forge one without the identity key. See `src/net/identity.ts`.
 *
 * ── What this is still not ────────────────────────────────────────────────
 * The handshake sends a bare 32-byte x-coordinate. That is better than a
 * compressed point, whose leading `0x02`/`0x03` byte is a free classifier
 * signal, but it is still not uniform: only about half of all 32-byte strings
 * are valid x-coordinates, so a determined classifier gets roughly one bit per
 * handshake. Making it indistinguishable needs ElligatorSwift, which is not
 * implemented — and hand-rolling it would be the same mistake as hand-rolling
 * BIP-340.
 */

import { createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';

import {
  concat,
  ecdh,
  equalBytes,
  pointFromSecret,
  randomPrivateKey,
  toHex,
  toXOnly,
  utf8,
  type Hex,
} from '../crypto.ts';
import { MAX_MESSAGE_BYTES } from '../params.ts';

/**
 * Ephemeral key exchanged in the clear, as a bare x-coordinate.
 *
 * 32 bytes rather than a 33-byte compressed point: the parity byte carries no
 * information the exchange needs — `ecdh` hashes only the x-coordinate — and a
 * constant leading `0x02`/`0x03` is a free signal to anyone classifying
 * traffic. Dropping it costs nothing and removes the most obvious tell.
 */
export const HANDSHAKE_BYTES = 32;
/** Encrypted length prefix. 3 bytes caps a frame at 16 MiB, well over the limit. */
export const LENGTH_BYTES = 3;
export const TAG_BYTES = 16;
export const KEY_BYTES = 32;
/** Frames before the keys are ratcheted forward. */
export const REKEY_INTERVAL = 4096;

const AEAD = 'chacha20-poly1305';

export interface SessionKeys {
  readonly send: Uint8Array;
  readonly recv: Uint8Array;
  readonly sendLength: Uint8Array;
  readonly recvLength: Uint8Array;
  /** Stable identifier for the session, safe to log. */
  readonly sessionId: Hex;
}

/**
 * Derive both directions' keys from a completed ECDH.
 *
 * `initiatorFirst` decides which half of the expanded material is "send" for
 * this side. Both ends compute the same expansion and pick opposite halves.
 */
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  network: string,
  keyA: Uint8Array,
  keyB: Uint8Array,
  weAreA: boolean,
): SessionKeys {
  // Sorting the two ephemeral keys gives both ends the same transcript without
  // needing to agree on who dialled whom.
  const [low, high] = compareBytes(keyA, keyB) <= 0 ? [keyA, keyB] : [keyB, keyA];
  const info = concat(utf8(`DeckxCoin/transport/v1/${network}`), low, high);
  const salt = utf8('DeckxCoin/transport/salt/v1');

  const material = new Uint8Array(
    hkdfSync('sha256', sharedSecret, salt, info, KEY_BYTES * 5),
  );

  const aKey = material.subarray(0, 32);
  const bKey = material.subarray(32, 64);
  const aLen = material.subarray(64, 96);
  const bLen = material.subarray(96, 128);
  const sessionId = material.subarray(128, 160);

  return {
    send: weAreA ? aKey : bKey,
    recv: weAreA ? bKey : aKey,
    sendLength: weAreA ? aLen : bLen,
    recvLength: weAreA ? bLen : aLen,
    sessionId: toHex(sessionId),
  };
}

/** 96-bit nonce: 32 zero bits then a 64-bit big-endian counter. */
function nonceFor(counter: bigint): Uint8Array {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  view.setBigUint64(4, counter, false);
  return out;
}

/**
 * ChaCha20 keystream used to mask the length prefix.
 *
 * Node exposes raw ChaCha20 as a cipher, so encrypting three zero bytes yields
 * three keystream bytes. Each frame uses its own counter as the nonce, so no
 * keystream byte is ever reused.
 *
 * OpenSSL's raw ChaCha20 takes a **16-byte** IV — a 4-byte little-endian block
 * counter followed by the 12-byte nonce — not the bare 12-byte nonce the AEAD
 * mode takes. Passing 12 bytes throws `Invalid initialization vector`, which
 * during development surfaced as a connection that handshook and then silently
 * never spoke.
 */
function lengthMask(key: Uint8Array, counter: bigint): Uint8Array {
  const iv = concat(new Uint8Array(4), nonceFor(counter));
  const cipher = createCipheriv('chacha20', key, iv);
  return new Uint8Array(cipher.update(new Uint8Array(LENGTH_BYTES)));
}

/** Ratchet a key forward. The old key cannot be recovered from the new one. */
function ratchet(key: Uint8Array, label: string): Uint8Array {
  return new Uint8Array(
    hkdfSync('sha256', key, utf8('DeckxCoin/transport/rekey'), utf8(label), KEY_BYTES),
  );
}

/**
 * One side of an encrypted session.
 *
 * Stateful in both directions: nonces are frame counters that must never
 * repeat, so a `Cipher` instance belongs to exactly one connection and cannot
 * be shared or reset.
 */
export class Cipher {
  #send: Uint8Array;
  #recv: Uint8Array;
  #sendLength: Uint8Array;
  #recvLength: Uint8Array;
  #sendCounter = 0n;
  #recvCounter = 0n;
  readonly sessionId: Hex;

  constructor(keys: SessionKeys) {
    this.#send = keys.send;
    this.#recv = keys.recv;
    this.#sendLength = keys.sendLength;
    this.#recvLength = keys.recvLength;
    this.sessionId = keys.sessionId;
  }

  get framesSent(): number {
    return Number(this.#sendCounter);
  }

  get framesReceived(): number {
    return Number(this.#recvCounter);
  }

  /** Wrap one payload into an encrypted frame. */
  seal(payload: Uint8Array): Uint8Array {
    if (payload.length > MAX_MESSAGE_BYTES) {
      throw new Error(`seal: payload of ${payload.length} bytes exceeds the cap`);
    }

    const counter = this.#sendCounter;
    const lengthPlain = writeLength(payload.length);
    const lengthCipher = xor(lengthPlain, lengthMask(this.#sendLength, counter));

    const cipher = createCipheriv(AEAD, this.#send, nonceFor(counter), { authTagLength: TAG_BYTES });
    // The encrypted length is authenticated, so it cannot be altered in flight.
    cipher.setAAD(lengthCipher);
    const body = concat(new Uint8Array(cipher.update(payload)), new Uint8Array(cipher.final()));
    const tag = new Uint8Array(cipher.getAuthTag());

    this.#advanceSend();
    return concat(lengthCipher, body, tag);
  }

  /**
   * Try to read one frame from the front of `buffer`.
   *
   * `consumed: 0` with no error means "need more bytes". Any error is fatal
   * for the connection — a stream that fails authentication cannot be
   * resynchronised, and trying to is how a decryption oracle gets built.
   */
  open(buffer: Uint8Array): { payload?: Uint8Array; consumed: number; error?: string } {
    if (buffer.length < LENGTH_BYTES) return { consumed: 0 };

    const counter = this.#recvCounter;
    const lengthCipher = buffer.subarray(0, LENGTH_BYTES);
    const length = readLength(xor(lengthCipher, lengthMask(this.#recvLength, counter)));

    if (length > MAX_MESSAGE_BYTES) {
      return { consumed: 0, error: `frame announces ${length} bytes, over the cap` };
    }

    const total = LENGTH_BYTES + length + TAG_BYTES;
    if (buffer.length < total) return { consumed: 0 };

    const body = buffer.subarray(LENGTH_BYTES, LENGTH_BYTES + length);
    const tag = buffer.subarray(LENGTH_BYTES + length, total);

    try {
      const decipher = createDecipheriv(AEAD, this.#recv, nonceFor(counter), {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(lengthCipher);
      decipher.setAuthTag(tag);
      const payload = concat(
        new Uint8Array(decipher.update(body)),
        new Uint8Array(decipher.final()),
      );
      this.#advanceRecv();
      return { payload, consumed: total };
    } catch {
      return { consumed: 0, error: 'frame failed authentication' };
    }
  }

  #advanceSend(): void {
    this.#sendCounter++;
    if (this.#sendCounter % BigInt(REKEY_INTERVAL) === 0n) {
      this.#send = ratchet(this.#send, 'send');
      this.#sendLength = ratchet(this.#sendLength, 'send-length');
    }
  }

  #advanceRecv(): void {
    this.#recvCounter++;
    if (this.#recvCounter % BigInt(REKEY_INTERVAL) === 0n) {
      this.#recv = ratchet(this.#recv, 'send');
      this.#recvLength = ratchet(this.#recvLength, 'send-length');
    }
  }
}

/* ────────────────────────────────────────────────────────── handshake ── */

export interface HandshakeResult {
  readonly cipher: Cipher;
  readonly peerEphemeral: Uint8Array;
}

/**
 * Drives the two-message key exchange.
 *
 * Deliberately transport-agnostic: it produces bytes to send and consumes
 * bytes received, so it can be unit-tested without a socket.
 */
export class Handshake {
  readonly #secret: Uint8Array;
  readonly ephemeral: Uint8Array;
  readonly #network: string;
  #done = false;

  constructor(network: string, secret: Uint8Array = randomPrivateKey()) {
    this.#network = network;
    this.#secret = secret;
    this.ephemeral = pointFromSecret(secret);
  }

  /** The bytes to put on the wire first, before anything else. */
  greeting(): Uint8Array {
    return toXOnly(this.ephemeral);
  }

  get complete(): boolean {
    return this.#done;
  }

  /**
   * Consume the peer's greeting and derive session keys.
   *
   * Rejects a peer that echoes our own ephemeral key: that is either a
   * reflection attack or a connection to ourselves, and completing the
   * handshake would produce a session where sending and receiving keys match.
   */
  accept(peerGreeting: Uint8Array): HandshakeResult {
    if (this.#done) throw new Error('handshake: already complete');
    if (peerGreeting.length !== HANDSHAKE_BYTES) {
      throw new Error(`handshake: expected ${HANDSHAKE_BYTES} bytes, got ${peerGreeting.length}`);
    }
    const ours = toXOnly(this.ephemeral);
    if (equalBytes(peerGreeting, ours)) {
      throw new Error('handshake: peer echoed our own ephemeral key');
    }

    // Lifting fails for 32 bytes that are not an x-coordinate on the curve,
    // which is how garbage is rejected before any key material is derived.
    const shared = ecdh(this.#secret, peerGreeting);
    // Sorting decides direction; whoever holds the lexicographically smaller
    // ephemeral key is "A". No role negotiation, no extra round trip.
    const weAreA = compareBytes(ours, peerGreeting) < 0;
    const keys = deriveSessionKeys(shared, this.#network, ours, peerGreeting, weAreA);

    this.#done = true;
    return { cipher: new Cipher(keys), peerEphemeral: peerGreeting };
  }
}

/* ──────────────────────────────────────────────────────────── helpers ── */

function writeLength(value: number): Uint8Array {
  return Uint8Array.of((value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff);
}

const readLength = (b: Uint8Array): number => (b[0] << 16) | (b[1] << 8) | b[2];

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
