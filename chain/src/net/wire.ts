/**
 * Wire protocol — framing and message types.
 *
 * Bitcoin's frame, because it has survived fifteen years of adversarial
 * traffic and there is nothing to improve:
 *
 *     magic (4) ‖ command (12, NUL-padded ASCII) ‖ length (4) ‖ checksum (4) ‖ payload
 *
 * Why each field earns its place:
 *
 *   magic     Makes a cross-network connection fail on the first frame rather
 *             than subtly, ten blocks later. Also resynchronises a stream that
 *             has somehow desynchronised.
 *   command   Human-readable in a packet capture. Debugging a network protocol
 *             you cannot read is miserable.
 *   length    Lets a reader know whether a full message has arrived before
 *             parsing anything. Checked against a hard cap first, so a peer
 *             cannot announce a 4 GB message and make us allocate it.
 *   checksum  First four bytes of the double-SHA-256. Catches corruption that
 *             TCP's 16-bit checksum misses, which at scale is not rare.
 *
 * Payloads are JSON. This is a deliberate trade: a compact binary encoding
 * would be maybe 60% smaller, and would also mean a second serialisation of
 * every consensus structure — a second place for the two to disagree. On a
 * reference chain, one canonical encoding beats a smaller one.
 */

import { concat, fromHex, sha256d, toHex, type Hex } from '../crypto.ts';
import { MAX_MESSAGE_BYTES } from '../params.ts';

export const HEADER_SIZE = 24;
export const COMMAND_SIZE = 12;

/** Protocol version. Bumped when a message's shape changes incompatibly. */
export const PROTOCOL_VERSION = 1;
/** Oldest version this build will talk to. */
export const MIN_PROTOCOL_VERSION = 1;

export const MSG = {
  /** Opening handshake. Must be the first message in each direction. */
  VERSION: 'version',
  /** Acknowledges a `version`. The connection is usable only after both sides send one. */
  VERACK: 'verack',
  PING: 'ping',
  PONG: 'pong',
  /** Request known peer addresses. */
  GETADDR: 'getaddr',
  /** Peer addresses, gossiped. */
  ADDR: 'addr',
  /** Announce that we have blocks or transactions, by id. */
  INV: 'inv',
  /** Request the full body of announced items. */
  GETDATA: 'getdata',
  /** Ask for headers after a locator. */
  GETHEADERS: 'getheaders',
  /** Headers, oldest first. */
  HEADERS: 'headers',
  BLOCK: 'block',
  TX: 'tx',
  /** Ask for the peer's mempool contents. */
  MEMPOOL: 'mempool',
  /** Tell a peer we refused something, and why. */
  REJECT: 'reject',
} as const;

export type MessageCommand = (typeof MSG)[keyof typeof MSG];

export const INV_TYPE = { TX: 'tx', BLOCK: 'block' } as const;
export type InvType = (typeof INV_TYPE)[keyof typeof INV_TYPE];

export interface InvItem {
  readonly type: InvType;
  readonly hash: Hex;
}

/* ─────────────────────────────────────────────────────── payload shapes ── */

export interface VersionPayload {
  readonly version: number;
  readonly network: string;
  /** Random per-connection value. Used to detect a connection to ourselves. */
  readonly nonce: string;
  readonly userAgent: string;
  /** Height of the sender's active chain. */
  readonly height: number;
  /** Sender's accumulated work, decimal string. */
  readonly chainWork: string;
  /** Port the sender listens on, so the receiver can gossip it onward. */
  readonly listenPort: number;
  readonly timestamp: number;
  /** Sender's genesis hash. A mismatch means incompatible chains. */
  readonly genesis: Hex;
  /**
   * Proof that the sender owns its long-term identity key, bound to this
   * session. Without it an active man-in-the-middle is undetectable.
   */
  readonly auth: { readonly identity: Hex; readonly signature: Hex };
}

export interface AddrPayload {
  readonly peers: ReadonlyArray<{ host: string; port: number; lastSeen: number }>;
}

export interface InvPayload {
  readonly items: readonly InvItem[];
}

export interface GetHeadersPayload {
  readonly locator: readonly Hex[];
  /** Stop when this hash is reached. All-zero means "as many as you have". */
  readonly stop: Hex;
}

export interface RejectPayload {
  readonly command: string;
  readonly reason: string;
  readonly hash?: Hex;
}

/* ─────────────────────────────────────────────────────────── encoding ── */

export interface WireMessage {
  readonly command: string;
  readonly payload: unknown;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function commandBytes(command: string): Uint8Array {
  const raw = encoder.encode(command);
  if (raw.length > COMMAND_SIZE) throw new Error(`command '${command}' exceeds ${COMMAND_SIZE} bytes`);
  const out = new Uint8Array(COMMAND_SIZE);
  out.set(raw, 0);
  return out;
}

function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
}

const readU32 = (b: Uint8Array, offset: number): number =>
  new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offset, false);

/** Serialise a message into a complete frame. */
export function encodeMessage(magic: number, command: string, payload: unknown): Uint8Array {
  const body = payload === undefined ? new Uint8Array(0) : encoder.encode(JSON.stringify(payload));
  if (body.length > MAX_MESSAGE_BYTES) {
    throw new Error(`message '${command}' is ${body.length} bytes, over the ${MAX_MESSAGE_BYTES} cap`);
  }
  const checksum = sha256d(body).subarray(0, 4);
  return concat(u32(magic), commandBytes(command), u32(body.length), checksum, body);
}

export interface DecodeResult {
  readonly message?: WireMessage;
  /** Bytes consumed. Zero means "need more data". */
  readonly consumed: number;
  readonly error?: string;
}

/**
 * Try to read one message from the front of `buffer`.
 *
 * Returns `consumed: 0` when the frame is incomplete — the caller keeps
 * buffering. Any framing error is fatal for the connection: a stream we cannot
 * parse is a stream we cannot trust to resynchronise.
 */
export function decodeMessage(magic: number, buffer: Uint8Array): DecodeResult {
  if (buffer.length < HEADER_SIZE) return { consumed: 0 };

  const gotMagic = readU32(buffer, 0);
  if (gotMagic !== (magic >>> 0)) {
    return {
      consumed: 0,
      error: `wrong network magic 0x${gotMagic.toString(16)} (expected 0x${(magic >>> 0).toString(16)})`,
    };
  }

  const command = decoder.decode(buffer.subarray(4, 4 + COMMAND_SIZE)).replace(/\0+$/, '');
  const length = readU32(buffer, 16);
  if (length > MAX_MESSAGE_BYTES) {
    return { consumed: 0, error: `announced message length ${length} exceeds the cap` };
  }

  if (buffer.length < HEADER_SIZE + length) return { consumed: 0 };

  const body = buffer.subarray(HEADER_SIZE, HEADER_SIZE + length);
  const expected = toHex(buffer.subarray(20, 24));
  const actual = toHex(sha256d(body).subarray(0, 4));
  if (expected !== actual) {
    return { consumed: 0, error: `checksum mismatch on '${command}': ${actual} != ${expected}` };
  }

  let payload: unknown;
  if (length > 0) {
    try {
      payload = JSON.parse(decoder.decode(body));
    } catch (err) {
      return { consumed: 0, error: `malformed JSON in '${command}': ${(err as Error).message}` };
    }
  }

  return { message: { command, payload }, consumed: HEADER_SIZE + length };
}

/** Random 8-byte connection nonce, hex. Used for self-connection detection. */
export function connectionNonce(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

export const ZERO_HASH: Hex = '0'.repeat(64);

export const isHash = (value: unknown): value is Hex =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

/** Reject a payload that is not shaped as expected, before it reaches consensus code. */
export function expectObject(payload: unknown, fields: readonly string[]): string | undefined {
  if (typeof payload !== 'object' || payload === null) return 'payload is not an object';
  for (const field of fields) {
    if (!(field in (payload as Record<string, unknown>))) return `missing field '${field}'`;
  }
  return undefined;
}

void fromHex;
