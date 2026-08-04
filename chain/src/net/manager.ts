/**
 * Peer manager.
 *
 * Owns the listening socket, the outbound dialler, the ban list, and the
 * address book. Everything above it (sync, relay, mempool) subscribes to
 * `message` events and calls `broadcast`/`send`; everything below it is a TCP
 * socket. It deliberately knows nothing about blocks.
 *
 * ── Connection policy ─────────────────────────────────────────────────────
 * Outbound slots are the ones that matter for security: a node that only ever
 * accepts inbound connections can be surrounded by an attacker who controls
 * every peer it sees. The manager therefore maintains its own outbound
 * connections to addresses it chose, from its own address book, and treats
 * inbound peers as a bonus rather than a substitute.
 */

import { createServer, Socket, type Server } from 'node:net';
import { EventEmitter } from 'node:events';

import { Peer, PEER_STATE, normaliseHost, type PeerInfo } from './peer.ts';
import { dialThroughProxy, routeFor, type ProxyConfig } from './socks.ts';
import { MSG, type AddrPayload, type WireMessage } from './wire.ts';
import {
  MAX_INBOUND_PEERS,
  MAX_OUTBOUND_PEERS,
  type NetworkParams,
} from '../params.ts';
import type { ChainStore } from '../store/sqlite.ts';
import type { Hex, KeyPair } from '../crypto.ts';
import { IDENTITY_VERDICT, isFatalVerdict, judgeIdentity } from './identity.ts';

export interface ManagerOptions {
  /** Route outbound connections through this SOCKS5 proxy. */
  readonly proxy?: ProxyConfig;
  readonly params: NetworkParams;
  readonly store: ChainStore;
  readonly listenPort: number;
  /**
   * SOCKS5 proxy for outbound connections, usually Tor.
   *
   * The transport is already encrypted and identity-bound, so nobody on the
   * path can read this node's traffic or impersonate its peers. None of that
   * hides *where it is* — a node dialling from its own address tells every peer
   * it meets, and the peer that receives a transaction first has a good guess
   * about who wrote it.
   */
  readonly proxy?: ProxyConfig;
  readonly listenHost?: string;
  readonly userAgent: string;
  readonly genesis: Hex;
  readonly localHeight: () => number;
  readonly localWork: () => bigint;
  /** This node's long-term identity. Proves who we are on every connection. */
  readonly identity: KeyPair;
  /** Set false for a node that should only make outbound connections. */
  readonly listen?: boolean;
  readonly maxOutbound?: number;
  readonly maxInbound?: number;
  /** How often to top up outbound connections, ms. */
  readonly dialIntervalMs?: number;
}

export interface BanRecord {
  readonly host: string;
  readonly until: number;
  readonly reason: string;
}

/** Bans expire; a node that misbehaved once should not be shunned forever. */
const BAN_DURATION_MS = 60 * 60 * 1000;

export class PeerManager extends EventEmitter {
  readonly params: NetworkParams;
  readonly store: ChainStore;
  readonly listenPort: number;

  readonly peers = new Map<string, Peer>();
  readonly #bans = new Map<string, BanRecord>();
  readonly #ourNonces = new Set<string>();
  readonly #dialling = new Set<string>();

  #server?: Server;
  #dialTimer?: NodeJS.Timeout;
  #running = false;
  readonly #opts: ManagerOptions;

  constructor(opts: ManagerOptions) {
    super();
    this.#opts = opts;
    this.params = opts.params;
    this.store = opts.store;
    this.listenPort = opts.listenPort;
    this.proxy = opts.proxy;
  }

  get outboundCount(): number {
    return [...this.peers.values()].filter((p) => p.outbound).length;
  }

  get inboundCount(): number {
    return [...this.peers.values()].filter((p) => !p.outbound).length;
  }

  get readyPeers(): Peer[] {
    return [...this.peers.values()].filter((p) => p.state === PEER_STATE.READY);
  }

  info(): PeerInfo[] {
    return [...this.peers.values()].map((p) => p.info());
  }

  bans(): BanRecord[] {
    this.#expireBans();
    return [...this.#bans.values()];
  }

  /* ──────────────────────────────────────────────────────── lifecycle ── */

  async start(): Promise<void> {
    if (this.#running) return;
    this.#running = true;

    if (this.#opts.listen !== false) {
      await this.#listen();
    }

    // Dial immediately, then keep topping up.
    this.#topUpOutbound();
    this.#dialTimer = setInterval(() => this.#topUpOutbound(), this.#opts.dialIntervalMs ?? 5_000);
    this.#dialTimer.unref?.();
  }

  async stop(): Promise<void> {
    this.#running = false;
    if (this.#dialTimer) clearInterval(this.#dialTimer);
    for (const peer of [...this.peers.values()]) peer.disconnect('node shutting down');
    this.peers.clear();
    if (this.#server) {
      await new Promise<void>((resolve) => this.#server!.close(() => resolve()));
      this.#server = undefined;
    }
  }

  #listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = createServer((socket) => this.#onInbound(socket));
      server.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });
      server.listen(this.listenPort, this.#opts.listenHost ?? '127.0.0.1', () => {
        this.#server = server;
        this.emit('listening', this.listenPort);
        resolve();
      });
      server.unref?.();
    });
  }

  /* ────────────────────────────────────────────────────── connections ── */

  #onInbound(socket: Socket): void {
    const host = normaliseHost(socket.remoteAddress ?? '');

    if (this.isBanned(host)) {
      socket.destroy();
      return;
    }
    if (this.inboundCount >= (this.#opts.maxInbound ?? MAX_INBOUND_PEERS)) {
      socket.destroy();
      return;
    }
    this.#attach(socket, false);
  }

  /**
   * Dial `host:port`. Resolves once the handshake completes or fails.
   *
   * `expectedIdentity` pins the peer's long-term key. When supplied, a peer
   * proving any other identity is refused outright — the strong defence
   * against a man in the middle.
   */
  connect(host: string, port: number, expectedIdentity?: Hex): Promise<Peer | undefined> {
    const key = `${host}:${port}`;
    if (this.isBanned(host)) return Promise.resolve(undefined);
    if (this.#dialling.has(key)) return Promise.resolve(undefined);
    if (this.#hasPeerAt(host, port)) return Promise.resolve(undefined);

    this.#dialling.add(key);

    return new Promise((resolve) => {
      let settled = false;
      const socket = new Socket();

      const fail = (reason: string) => {
        if (settled) return;
        settled = true;
        this.#dialling.delete(key);
        this.store.rememberPeer(host, port, false);
        socket.destroy();
        this.emit('dialFailed', { host, port, reason });
        resolve(undefined);
      };

      const ready = (connected: Socket) => {
        connected.setTimeout(0);
        this.#dialling.delete(key);
        const peer = this.#attach(connected, true, port, expectedIdentity);
        peer.once('ready', () => {
          if (settled) return;
          settled = true;
          this.store.rememberPeer(host, port, true);
          resolve(peer);
        });
        peer.once('disconnect', () => {
          if (settled) return;
          settled = true;
          resolve(undefined);
        });
      };

      /*
       * Through a proxy when one is configured, and always for a `.onion`
       * address — which names no IP and cannot be reached any other way. The
       * encrypted transport above does not need to know the difference; it
       * gets a connected socket either way.
       */
      const route = routeFor(host, this.proxy);
      if (route.error) return fail(route.error);

      if (route.via === 'proxy') {
        dialThroughProxy({ proxy: this.proxy!, host, port, timeoutMs: 30_000 }).then(ready, (err) =>
          fail((err as Error).message),
        );
        return;
      }

      socket.setTimeout(10_000, () => fail('connect timeout'));
      socket.once('error', (err) => fail(err.message));
      socket.connect(port, host, () => ready(socket));
    });
  }

  #attach(
    socket: Socket,
    outbound: boolean,
    knownListenPort?: number,
    expectedIdentity?: Hex,
  ): Peer {
    const peer = new Peer({
      params: this.params,
      socket,
      outbound,
      listenPort: this.listenPort,
      userAgent: this.#opts.userAgent,
      localHeight: this.#opts.localHeight,
      localWork: this.#opts.localWork,
      genesis: this.#opts.genesis,
      ourNonces: this.#ourNonces,
      identity: this.#opts.identity,
      expectedIdentity,
    });
    if (knownListenPort) peer.listenPort = knownListenPort;

    this.peers.set(peer.id, peer);

    peer.on('ready', () => {
      const addr = peer.advertisedAddress;

      /*
       * Trust on first use. The signature already proved the peer owns *some*
       * identity; this decides whether it is the identity we saw last time. A
       * change means either the operator re-keyed or somebody is in the
       * middle, and the two are indistinguishable from here — so it is fatal
       * and loud, exactly as SSH treats it.
       */
      if (addr && !expectedIdentity) {
        const judged = judgeIdentity(this.store, addr.host, addr.port, peer.peerIdentity);
        if (isFatalVerdict(judged.verdict)) {
          this.emit('identityChanged', {
            host: addr.host,
            port: addr.port,
            previous: judged.previous,
            current: peer.peerIdentity,
          });
          peer.disconnect(
            `identity for ${addr.host}:${addr.port} changed from ` +
              `${judged.previous?.slice(0, 16)}… to ${peer.peerIdentity.slice(0, 16)}…`,
          );
          return;
        }
        if (judged.verdict === IDENTITY_VERDICT.NEW) {
          this.emit('identityLearned', {
            host: addr.host,
            port: addr.port,
            identity: peer.peerIdentity,
          });
        }
      }

      if (addr) this.store.rememberPeer(addr.host, addr.port, true);
      // Ask a new peer who else it knows. This is the whole of peer discovery.
      peer.send(MSG.GETADDR, {});
      this.emit('peerReady', peer);
    });

    peer.on('message', (message: WireMessage, from: Peer) => {
      if (message.command === MSG.GETADDR) {
        this.#sendAddresses(from);
        return;
      }
      if (message.command === MSG.ADDR) {
        this.#onAddr(message.payload as AddrPayload, from);
        return;
      }
      this.emit('message', message, from);
    });

    peer.on('misbehaviour', (detail, from: Peer) => this.emit('misbehaviour', detail, from));

    peer.on('ban', (reason: string, from: Peer) => {
      const host = normaliseHost(from.host);
      this.#bans.set(host, { host, until: Date.now() + BAN_DURATION_MS, reason });
      const addr = from.advertisedAddress;
      if (addr) this.store.forgetPeer(addr.host, addr.port);
      this.emit('banned', { host, reason });
    });

    peer.on('disconnect', (reason: string, from: Peer) => {
      this.peers.delete(from.id);
      this.emit('peerGone', from, reason);
    });

    peer.on('error', () => {
      /* Socket errors surface as a disconnect; nothing else to do. */
    });

    peer.start();
    return peer;
  }

  #hasPeerAt(host: string, port: number): boolean {
    const target = normaliseHost(host);
    for (const peer of this.peers.values()) {
      if (normaliseHost(peer.host) === target && (peer.port === port || peer.listenPort === port)) {
        return true;
      }
    }
    return false;
  }

  /* ──────────────────────────────────────────────────────── discovery ── */

  #topUpOutbound(): void {
    if (!this.#running) return;
    const want = this.#opts.maxOutbound ?? MAX_OUTBOUND_PEERS;
    if (this.outboundCount >= want) return;

    const candidates = [
      ...this.store.knownPeers(64),
      ...this.params.seeds.map((seed) => {
        const [host, port] = splitHostPort(seed, this.params.defaultPort);
        return { host, port, lastSeen: 0, lastSuccess: 0, failures: 0 };
      }),
    ];

    for (const candidate of candidates) {
      if (this.outboundCount + this.#dialling.size >= want) break;
      if (candidate.port === this.listenPort && isLocal(candidate.host)) continue;
      if (this.#hasPeerAt(candidate.host, candidate.port)) continue;
      if (this.isBanned(candidate.host)) continue;
      void this.connect(candidate.host, candidate.port);
    }
  }

  #sendAddresses(to: Peer): void {
    const known = this.store.knownPeers(32).map((p) => ({
      host: p.host,
      port: p.port,
      lastSeen: p.lastSeen,
    }));
    // Include ourselves so the peer can tell others about us.
    known.unshift({ host: '127.0.0.1', port: this.listenPort, lastSeen: Math.floor(Date.now() / 1000) });
    to.send(MSG.ADDR, { peers: known.slice(0, 32) } satisfies AddrPayload);
  }

  #onAddr(payload: AddrPayload, from: Peer): void {
    if (!payload || !Array.isArray(payload.peers)) {
      from.misbehave(10, 'malformed addr payload');
      return;
    }
    if (payload.peers.length > 64) {
      from.misbehave(10, `addr message carried ${payload.peers.length} entries`);
      return;
    }
    for (const entry of payload.peers) {
      const port = Number(entry.port);
      if (!entry.host || !Number.isInteger(port) || port <= 0 || port > 65535) continue;
      if (port === this.listenPort && isLocal(entry.host)) continue;
      this.store.rememberPeer(String(entry.host).slice(0, 64), port, false);
    }
    this.emit('addr', payload.peers.length, from);
  }

  /* ─────────────────────────────────────────────────────────── bans ── */

  isBanned(host: string): boolean {
    this.#expireBans();
    return this.#bans.has(normaliseHost(host));
  }

  #expireBans(): void {
    const now = Date.now();
    for (const [host, record] of this.#bans) {
      if (record.until <= now) this.#bans.delete(host);
    }
  }

  /* ────────────────────────────────────────────────────────── relay ── */

  /** Send to every ready peer, optionally skipping the one that told us. */
  broadcast(command: string, payload: unknown, except?: Peer): number {
    let sent = 0;
    for (const peer of this.readyPeers) {
      if (peer === except) continue;
      peer.send(command, payload);
      sent++;
    }
    return sent;
  }

  /** The ready peer claiming the most work, for headers-first sync. */
  bestPeer(): Peer | undefined {
    let best: Peer | undefined;
    for (const peer of this.readyPeers) {
      if (!best || peer.chainWork > best.chainWork) best = peer;
    }
    return best;
  }
}

function splitHostPort(value: string, defaultPort: number): [string, number] {
  const idx = value.lastIndexOf(':');
  if (idx === -1) return [value, defaultPort];
  return [value.slice(0, idx), Number(value.slice(idx + 1)) || defaultPort];
}

const isLocal = (host: string): boolean =>
  ['127.0.0.1', 'localhost', '::1', '0.0.0.0'].includes(normaliseHost(host));
