/**
 * A single peer connection.
 *
 * Owns exactly one TCP socket and the state machine over it: buffer bytes,
 * decode frames, run the handshake, emit typed messages, and keep a ban score.
 * It knows nothing about the chain — routing messages to consensus is the
 * manager's job. That separation is what makes the protocol testable without
 * a chain and the chain testable without sockets.
 *
 * ── Ban scoring ───────────────────────────────────────────────────────────
 * Misbehaviour adds points; 100 disconnects and blocks the address. The scale
 * is deliberate:
 *
 *   1    unsolicited or unparseable-but-harmless message — could be a version skew
 *   10   protocol violation that a correct peer would not commit
 *   50   sending an object that fails validation
 *   100  sending an invalid block, or a framing error
 *
 * A peer that is merely slow or out of date is never banned. Banning honest
 * nodes for being behind is how a network partitions itself.
 */

import { Socket } from 'node:net';
import { EventEmitter } from 'node:events';

import {
  decodeMessage,
  encodeMessage,
  MSG,
  PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  connectionNonce,
  type VersionPayload,
  type WireMessage,
} from './wire.ts';
import { Cipher, Handshake, HANDSHAKE_BYTES } from './transport.ts';
import { BAN_THRESHOLD, PEER_TIMEOUT, PING_INTERVAL, type NetworkParams } from '../params.ts';
import type { Hex } from '../crypto.ts';

export const PEER_STATE = {
  CONNECTING: 'connecting',
  HANDSHAKING: 'handshaking',
  READY: 'ready',
  CLOSED: 'closed',
} as const;

export type PeerState = (typeof PEER_STATE)[keyof typeof PEER_STATE];

export interface PeerOptions {
  readonly params: NetworkParams;
  readonly socket: Socket;
  /** True when we dialled them; false when they dialled us. */
  readonly outbound: boolean;
  /** Our listening port, advertised so they can gossip it. */
  readonly listenPort: number;
  readonly userAgent: string;
  /** Our chain tip, sampled at handshake time. */
  readonly localHeight: () => number;
  readonly localWork: () => bigint;
  readonly genesis: Hex;
  /** Nonces of our own open connections, for self-connection detection. */
  readonly ourNonces: Set<string>;
}

export interface PeerInfo {
  readonly id: string;
  readonly host: string;
  readonly port: number;
  readonly outbound: boolean;
  readonly state: PeerState;
  readonly userAgent: string;
  readonly version: number;
  readonly height: number;
  readonly chainWork: string;
  readonly banScore: number;
  readonly connectedAt: number;
  readonly bytesSent: number;
  readonly bytesReceived: number;
  readonly lastMessageAt: number;
  readonly encrypted: boolean;
  /** Session identifier. Safe to log — it is derived material, not a key. */
  readonly sessionId: string;
}

export class Peer extends EventEmitter {
  readonly params: NetworkParams;
  readonly socket: Socket;
  readonly outbound: boolean;
  readonly nonce = connectionNonce();
  readonly connectedAt = Date.now();

  state: PeerState = PEER_STATE.CONNECTING;
  /** Port the peer listens on — only known after the handshake. */
  listenPort = 0;
  userAgent = '';
  version = 0;
  height = -1;
  chainWork = 0n;
  banScore = 0;
  bytesSent = 0;
  bytesReceived = 0;
  lastMessageAt = Date.now();

  #buffer = new Uint8Array(0);
  #sentVersion = false;
  #gotVersion = false;
  #gotVerack = false;
  #pingTimer?: NodeJS.Timeout;
  #lastPingNonce?: string;
  readonly #opts: PeerOptions;

  /* --- encrypted transport ------------------------------------------- */
  readonly #handshake: Handshake;
  #cipher?: Cipher;
  /** Session identifier, available once the key exchange completes. */
  sessionId = '';

  constructor(opts: PeerOptions) {
    super();
    this.#opts = opts;
    this.params = opts.params;
    this.socket = opts.socket;
    this.outbound = opts.outbound;
    this.#handshake = new Handshake(opts.params.name);

    opts.ourNonces.add(this.nonce);

    this.socket.on('data', (chunk: Buffer) => this.#onData(chunk));
    this.socket.on('error', (err) => this.emit('error', err));
    this.socket.on('close', () => this.#onClose());
    this.socket.setNoDelay(true);
  }

  /** True once the key exchange has completed and traffic is encrypted. */
  get encrypted(): boolean {
    return this.#cipher !== undefined;
  }

  get id(): string {
    return `${this.host}:${this.port}`;
  }

  get host(): string {
    return this.socket.remoteAddress ?? 'unknown';
  }

  get port(): number {
    return this.socket.remotePort ?? 0;
  }

  /** Address to gossip: their listening port, not their ephemeral source port. */
  get advertisedAddress(): { host: string; port: number } | undefined {
    if (!this.listenPort) return undefined;
    return { host: normaliseHost(this.host), port: this.listenPort };
  }

  info(): PeerInfo {
    return {
      id: this.id,
      host: normaliseHost(this.host),
      port: this.port,
      outbound: this.outbound,
      state: this.state,
      userAgent: this.userAgent,
      version: this.version,
      height: this.height,
      chainWork: this.chainWork.toString(),
      banScore: this.banScore,
      connectedAt: this.connectedAt,
      bytesSent: this.bytesSent,
      bytesReceived: this.bytesReceived,
      lastMessageAt: this.lastMessageAt,
      encrypted: this.encrypted,
      sessionId: this.sessionId,
    };
  }

  /* ──────────────────────────────────────────────────────── handshake ── */

  /**
   * Begin the connection.
   *
   * The very first bytes on the wire are our ephemeral public key, sent in the
   * clear — there is no key to encrypt it with yet. Everything after that,
   * including `version`, travels inside the encrypted channel.
   */
  start(): void {
    if (this.state !== PEER_STATE.CONNECTING) return;
    this.state = PEER_STATE.HANDSHAKING;
    this.socket.write(this.#handshake.greeting());
    this.bytesSent += HANDSHAKE_BYTES;
  }

  /** Send our `version`, once the channel is encrypted. */
  #sendVersion(): void {
    if (this.#sentVersion) return;
    this.#sentVersion = true;

    const payload: VersionPayload = {
      version: PROTOCOL_VERSION,
      network: this.params.name,
      nonce: this.nonce,
      userAgent: this.#opts.userAgent,
      height: this.#opts.localHeight(),
      chainWork: this.#opts.localWork().toString(),
      listenPort: this.#opts.listenPort,
      timestamp: Math.floor(Date.now() / 1000),
      genesis: this.#opts.genesis,
    };
    this.send(MSG.VERSION, payload);
  }

  #onVersion(payload: VersionPayload): void {
    if (this.#gotVersion) {
      this.misbehave(10, 'duplicate version message');
      return;
    }
    this.#gotVersion = true;

    // Connecting to ourselves wastes a slot and pollutes the address book.
    if (this.#opts.ourNonces.has(payload.nonce) && payload.nonce !== this.nonce) {
      this.disconnect('connected to self');
      return;
    }
    if (payload.version < MIN_PROTOCOL_VERSION) {
      this.disconnect(`protocol version ${payload.version} is below the minimum ${MIN_PROTOCOL_VERSION}`);
      return;
    }
    if (payload.network !== this.params.name) {
      this.disconnect(`peer is on '${payload.network}', we are on '${this.params.name}'`);
      return;
    }
    if (payload.genesis !== this.#opts.genesis) {
      // Same network name, different genesis: incompatible chains. Dropping
      // immediately is far better than syncing garbage for an hour.
      this.disconnect(`genesis mismatch: peer has ${payload.genesis}`);
      return;
    }

    this.version = payload.version;
    this.userAgent = String(payload.userAgent ?? '').slice(0, 64);
    this.height = Number(payload.height) || 0;
    this.listenPort = Number(payload.listenPort) || 0;
    try {
      this.chainWork = BigInt(payload.chainWork ?? '0');
    } catch {
      this.chainWork = 0n;
    }

    this.send(MSG.VERACK, {});
    this.#maybeReady();
  }

  #maybeReady(): void {
    if (this.state === PEER_STATE.READY) return;
    if (!this.#gotVersion || !this.#gotVerack) return;
    this.state = PEER_STATE.READY;
    this.#startPinging();
    this.emit('ready', this);
  }

  /* ───────────────────────────────────────────────────────────── i/o ── */

  send(command: string, payload?: unknown): void {
    if (this.socket.destroyed) return;
    if (!this.#cipher) {
      // Nothing may be sent before the key exchange completes. Silently
      // dropping would hide a protocol bug; this surfaces it.
      this.emit('error', new Error(`send('${command}') before the channel was encrypted`));
      return;
    }
    try {
      const frame = this.#cipher.seal(encodeMessage(this.params.magic, command, payload));
      this.bytesSent += frame.length;
      this.socket.write(frame);
    } catch (err) {
      this.emit('error', err);
    }
  }

  #onData(chunk: Buffer): void {
    this.bytesReceived += chunk.length;
    this.lastMessageAt = Date.now();

    const merged = new Uint8Array(this.#buffer.length + chunk.length);
    merged.set(this.#buffer, 0);
    merged.set(chunk, this.#buffer.length);
    this.#buffer = merged;

    // The first HANDSHAKE_BYTES are the peer's ephemeral key, in the clear.
    if (!this.#cipher) {
      if (this.#buffer.length < HANDSHAKE_BYTES) return;
      const greeting = this.#buffer.subarray(0, HANDSHAKE_BYTES);
      this.#buffer = this.#buffer.subarray(HANDSHAKE_BYTES);
      try {
        const result = this.#handshake.accept(greeting);
        this.#cipher = result.cipher;
        this.sessionId = result.cipher.sessionId;
      } catch (err) {
        this.disconnect(`key exchange failed: ${(err as Error).message}`);
        return;
      }
      this.emit('encrypted', this);
      this.#sendVersion();
    }

    // Drain every complete encrypted frame currently buffered.
    for (;;) {
      const opened = this.#cipher.open(this.#buffer);
      if (opened.error) {
        this.misbehave(100, opened.error);
        return;
      }
      if (opened.consumed === 0 || !opened.payload) return;
      this.#buffer = this.#buffer.subarray(opened.consumed);

      const result = decodeMessage(this.params.magic, opened.payload);
      if (result.error) {
        this.misbehave(100, result.error);
        return;
      }
      if (!result.message) {
        this.misbehave(100, 'authenticated frame did not contain a complete message');
        return;
      }
      this.#dispatch(result.message);
      if (this.state === PEER_STATE.CLOSED) return;
    }
  }

  #dispatch(message: WireMessage): void {
    // Only `version` and `verack` are legal before the handshake completes.
    if (this.state !== PEER_STATE.READY) {
      if (message.command === MSG.VERSION) {
        this.#onVersion(message.payload as VersionPayload);
        return;
      }
      if (message.command === MSG.VERACK) {
        this.#gotVerack = true;
        this.#maybeReady();
        return;
      }
      this.misbehave(10, `'${message.command}' received before the handshake completed`);
      return;
    }

    switch (message.command) {
      case MSG.PING:
        this.send(MSG.PONG, message.payload);
        return;
      case MSG.PONG: {
        const nonce = (message.payload as { nonce?: string } | undefined)?.nonce;
        if (this.#lastPingNonce && nonce !== this.#lastPingNonce) {
          this.misbehave(1, 'pong nonce did not match the ping');
        }
        this.#lastPingNonce = undefined;
        return;
      }
      case MSG.VERSION:
        this.misbehave(10, 'version sent after handshake');
        return;
      default:
        this.emit('message', message, this);
    }
  }

  /* ────────────────────────────────────────────────────── keep-alive ── */

  #startPinging(): void {
    this.#pingTimer = setInterval(() => {
      const silent = (Date.now() - this.lastMessageAt) / 1000;
      if (silent > PEER_TIMEOUT) {
        this.disconnect(`no traffic for ${Math.round(silent)}s`);
        return;
      }
      if (silent > PING_INTERVAL) {
        this.#lastPingNonce = connectionNonce();
        this.send(MSG.PING, { nonce: this.#lastPingNonce });
      }
    }, PING_INTERVAL * 1000);
    // Never hold the process open for a heartbeat.
    this.#pingTimer.unref?.();
  }

  /* ──────────────────────────────────────────────────────── lifecycle ── */

  /**
   * Record misbehaviour. Disconnects and signals a ban once the score reaches
   * the threshold.
   */
  misbehave(points: number, reason: string): void {
    this.banScore += points;
    this.emit('misbehaviour', { points, reason, score: this.banScore }, this);
    if (this.banScore >= BAN_THRESHOLD) {
      this.emit('ban', reason, this);
      this.disconnect(`banned: ${reason}`);
    }
  }

  disconnect(reason: string): void {
    if (this.state === PEER_STATE.CLOSED) return;
    this.state = PEER_STATE.CLOSED;
    this.emit('disconnect', reason, this);
    this.#cleanup();
    this.socket.destroy();
  }

  #onClose(): void {
    if (this.state === PEER_STATE.CLOSED) return;
    this.state = PEER_STATE.CLOSED;
    this.emit('disconnect', 'socket closed', this);
    this.#cleanup();
  }

  #cleanup(): void {
    if (this.#pingTimer) clearInterval(this.#pingTimer);
    this.#opts.ourNonces.delete(this.nonce);
    this.#buffer = new Uint8Array(0);
  }
}

/** Strip the IPv4-mapped IPv6 prefix Node reports for dual-stack sockets. */
export function normaliseHost(host: string): string {
  return host.startsWith('::ffff:') ? host.slice(7) : host;
}
