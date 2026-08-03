/**
 * DeckxNode — a full node.
 *
 * Wires the pieces together: `ChainState` for consensus and persistence,
 * `Mempool` for unconfirmed transactions, `PeerManager` for the network. This
 * file is the only place where those three meet, and it holds the policy that
 * connects them:
 *
 *   • **Sync.** Headers-first is the right shape, but a reference node can be
 *     simpler and still correct: on connect, ask the best peer for headers
 *     after our locator, then request the bodies in order. Blocks arriving out
 *     of order are held as orphans until their parent shows up.
 *   • **Relay.** Announce by inventory, never by pushing bodies. A peer that
 *     already has the block says nothing; one that does not asks for it. This
 *     is what keeps bandwidth linear in blocks rather than in peers×blocks.
 *   • **Reorg bookkeeping.** When the tip moves, the mempool is told what left
 *     the chain and what joined it. Skipping this is how a node ends up
 *     relaying transactions that a reorg already invalidated.
 */

import { EventEmitter } from 'node:events';

import { ChainState, ACCEPT, type AcceptResult } from './chainstate.ts';
import { Mempool } from './mempool.ts';
import { PeerManager } from '../net/manager.ts';
import { Peer } from '../net/peer.ts';
import {
  INV_TYPE,
  MSG,
  ZERO_HASH,
  expectObject,
  isHash,
  type GetHeadersPayload,
  type InvItem,
  type InvPayload,
  type RejectPayload,
  type WireMessage,
} from '../net/wire.ts';
import { MAX_HEADERS_PER_MESSAGE, MAX_INV_PER_MESSAGE, type NetworkParams } from '../params.ts';
import { ChainStore } from '../store/sqlite.ts';
import { blockHash, type Block } from '../block.ts';
import { txid, type Transaction } from '../tx.ts';
import { toHex, type Hex, type KeyPair } from '../crypto.ts';
import { loadIdentity, parsePeerAddress } from '../net/identity.ts';
import { tmpdir } from 'node:os';

export interface NodeOptions {
  readonly params: NetworkParams;
  readonly datadir: string;
  readonly listenPort?: number;
  readonly listenHost?: string;
  readonly listen?: boolean;
  readonly userAgent?: string;
  readonly maxOutbound?: number;
  readonly maxInbound?: number;
  readonly dialIntervalMs?: number;
  /** Addresses to dial at startup: `host:port`, optionally `#identity` to pin. */
  readonly connect?: readonly string[];
  readonly undoRetention?: number;
  /** Long-term identity. Generated and persisted in the datadir when omitted. */
  readonly identity?: KeyPair;
}

/** Orphans are bounded — an attacker must not be able to fill memory with them. */
const MAX_ORPHANS = 100;

export class DeckxNode extends EventEmitter {
  readonly params: NetworkParams;
  readonly store: ChainStore;
  readonly chain: ChainState;
  readonly mempool: Mempool;
  readonly net: PeerManager;
  /** This node's long-term identity, proven on every connection. */
  readonly identity: KeyPair;

  /** Blocks whose parent we do not have yet, keyed by their own hash. */
  readonly #orphans = new Map<Hex, Block>();
  /** Bodies we have asked for and not yet received. */
  readonly #inFlight = new Set<Hex>();
  #started = false;

  constructor(opts: NodeOptions) {
    super();
    this.params = opts.params;

    this.store = new ChainStore(
      opts.datadir === ':memory:' ? ':memory:' : `${opts.datadir}/chain.sqlite`,
    );
    this.chain = ChainState.open({
      params: opts.params,
      store: this.store,
      undoRetention: opts.undoRetention,
    });
    this.mempool = new Mempool();

    this.identity =
      opts.identity ??
      loadIdentity(
        opts.datadir === ':memory:'
          ? `${tmpdir()}/deckx-identity-${process.pid}`
          : `${opts.datadir}/identity`,
      );

    this.net = new PeerManager({
      params: opts.params,
      store: this.store,
      listenPort: opts.listenPort ?? opts.params.defaultPort,
      listenHost: opts.listenHost,
      listen: opts.listen,
      userAgent: opts.userAgent ?? `deckxd:0.2.0/${opts.params.name}`,
      genesis: this.chain.headerAt(0)!.hash,
      localHeight: () => this.chain.height,
      localWork: () => this.chain.chainWork,
      maxOutbound: opts.maxOutbound,
      maxInbound: opts.maxInbound,
      dialIntervalMs: opts.dialIntervalMs,
      identity: this.identity,
    });

    this.#wire();
    this.#initialPeers = opts.connect ?? [];
  }

  readonly #initialPeers: readonly string[];

  /* ──────────────────────────────────────────────────────── lifecycle ── */

  async start(): Promise<void> {
    if (this.#started) return;
    this.#started = true;
    await this.net.start();

    for (const address of this.#initialPeers) {
      // `host:port` or `host:port#identity` — the latter pins the peer's key.
      const target = parsePeerAddress(address, this.params.defaultPort);
      void this.net.connect(target.host, target.port, target.identity);
    }
    this.emit('started', this.info());
  }

  async stop(): Promise<void> {
    this.#started = false;
    await this.net.stop();
    this.store.close();
    this.emit('stopped');
  }

  info() {
    return {
      ...this.chain.info(),
      identity: toHex(this.identity.publicKey),
      userAgent: this.net.readyPeers.length,
      listenPort: this.net.listenPort,
      peers: this.net.peers.size,
      outbound: this.net.outboundCount,
      inbound: this.net.inboundCount,
      mempool: this.mempool.stats(),
      orphans: this.#orphans.size,
    };
  }

  /* ─────────────────────────────────────────────────── message routing ── */

  #wire(): void {
    this.net.on('peerReady', (peer: Peer) => {
      this.emit('peerReady', peer.info());
      // A peer claiming more work than us is worth syncing from.
      if (peer.chainWork > this.chain.chainWork) this.#requestHeaders(peer);
    });

    this.net.on('peerGone', (peer: Peer, reason: string) => {
      this.emit('peerGone', peer.info(), reason);
    });

    this.net.on('message', (message: WireMessage, peer: Peer) => {
      try {
        this.#onMessage(message, peer);
      } catch (err) {
        peer.misbehave(10, `handler threw: ${(err as Error).message}`);
      }
    });

    this.net.on('banned', (detail) => this.emit('banned', detail));
    this.net.on('identityChanged', (detail) => this.emit('identityChanged', detail));
    this.net.on('identityLearned', (detail) => this.emit('identityLearned', detail));
    this.net.on('error', (err) => this.emit('error', err));
  }

  #onMessage(message: WireMessage, peer: Peer): void {
    switch (message.command) {
      case MSG.INV:
        this.#onInv(message.payload as InvPayload, peer);
        return;
      case MSG.GETDATA:
        this.#onGetData(message.payload as InvPayload, peer);
        return;
      case MSG.GETHEADERS:
        this.#onGetHeaders(message.payload as GetHeadersPayload, peer);
        return;
      case MSG.HEADERS:
        this.#onHeaders(message.payload, peer);
        return;
      case MSG.BLOCK:
        this.#onBlock(message.payload as Block, peer);
        return;
      case MSG.TX:
        this.#onTx(message.payload as Transaction, peer);
        return;
      case MSG.MEMPOOL:
        this.#onMempoolRequest(peer);
        return;
      case MSG.REJECT:
        this.emit('reject', message.payload as RejectPayload, peer.info());
        return;
      default:
        peer.misbehave(1, `unknown command '${message.command}'`);
    }
  }

  /* ─────────────────────────────────────────────────────── inventory ── */

  #onInv(payload: InvPayload, peer: Peer): void {
    const problem = expectObject(payload, ['items']);
    if (problem || !Array.isArray(payload.items)) {
      peer.misbehave(10, `malformed inv: ${problem ?? 'items is not an array'}`);
      return;
    }
    if (payload.items.length > MAX_INV_PER_MESSAGE) {
      peer.misbehave(10, `inv carried ${payload.items.length} entries`);
      return;
    }

    const wanted: InvItem[] = [];
    for (const item of payload.items) {
      if (!isHash(item?.hash)) {
        peer.misbehave(10, 'inv entry has a malformed hash');
        return;
      }
      if (item.type === INV_TYPE.BLOCK) {
        if (this.chain.hasBlock(item.hash) || this.#inFlight.has(item.hash)) continue;
        this.#inFlight.add(item.hash);
        wanted.push(item);
      } else if (item.type === INV_TYPE.TX) {
        if (this.mempool.has(item.hash) || this.#inFlight.has(item.hash)) continue;
        this.#inFlight.add(item.hash);
        wanted.push(item);
      }
    }

    if (wanted.length > 0) peer.send(MSG.GETDATA, { items: wanted } satisfies InvPayload);
  }

  #onGetData(payload: InvPayload, peer: Peer): void {
    if (!payload || !Array.isArray(payload.items)) {
      peer.misbehave(10, 'malformed getdata');
      return;
    }
    if (payload.items.length > MAX_INV_PER_MESSAGE) {
      peer.misbehave(10, `getdata requested ${payload.items.length} items`);
      return;
    }

    for (const item of payload.items) {
      if (!isHash(item?.hash)) continue;
      if (item.type === INV_TYPE.BLOCK) {
        const block = this.chain.getBlock(item.hash);
        if (block) peer.send(MSG.BLOCK, block);
      } else if (item.type === INV_TYPE.TX) {
        const tx = this.mempool.get(item.hash);
        if (tx) peer.send(MSG.TX, tx);
      }
    }
  }

  /* ───────────────────────────────────────────────────────── headers ── */

  #requestHeaders(peer: Peer): void {
    peer.send(MSG.GETHEADERS, {
      locator: this.chain.locator(),
      stop: ZERO_HASH,
    } satisfies GetHeadersPayload);
  }

  #onGetHeaders(payload: GetHeadersPayload, peer: Peer): void {
    if (!payload || !Array.isArray(payload.locator)) {
      peer.misbehave(10, 'malformed getheaders');
      return;
    }
    const fork = this.chain.findForkPoint(payload.locator.filter(isHash));
    const headers = this.store
      .activeHeaders(fork.height + 1, MAX_HEADERS_PER_MESSAGE)
      .map((h) => ({ hash: h.hash, height: h.height }));
    peer.send(MSG.HEADERS, { headers });
  }

  #onHeaders(payload: unknown, peer: Peer): void {
    const headers = (payload as { headers?: Array<{ hash: Hex; height: number }> })?.headers;
    if (!Array.isArray(headers)) {
      peer.misbehave(10, 'malformed headers');
      return;
    }
    if (headers.length === 0) return;
    if (headers.length > MAX_HEADERS_PER_MESSAGE) {
      peer.misbehave(10, `headers carried ${headers.length} entries`);
      return;
    }

    // Ask for the bodies we do not already have, in chain order.
    const wanted: InvItem[] = [];
    for (const header of headers) {
      if (!isHash(header?.hash)) {
        peer.misbehave(10, 'header entry has a malformed hash');
        return;
      }
      if (this.chain.hasBlock(header.hash) || this.#inFlight.has(header.hash)) continue;
      this.#inFlight.add(header.hash);
      wanted.push({ type: INV_TYPE.BLOCK, hash: header.hash });
      if (wanted.length >= MAX_INV_PER_MESSAGE) break;
    }
    if (wanted.length > 0) peer.send(MSG.GETDATA, { items: wanted } satisfies InvPayload);
  }

  /* ────────────────────────────────────────────────────────── blocks ── */

  #onBlock(block: Block, peer: Peer): void {
    if (!block?.header || !Array.isArray(block.transactions)) {
      peer.misbehave(20, 'malformed block');
      return;
    }

    let hash: Hex;
    try {
      hash = blockHash(block.header);
    } catch {
      peer.misbehave(20, 'block header could not be hashed');
      return;
    }
    this.#inFlight.delete(hash);

    const result = this.submitBlock(block);

    switch (result.status) {
      case ACCEPT.INVALID:
        peer.misbehave(100, `invalid block ${hash}: ${result.error}`);
        peer.send(MSG.REJECT, { command: MSG.BLOCK, reason: result.error ?? 'invalid', hash });
        return;

      case ACCEPT.ORPHAN:
        this.#rememberOrphan(hash, block);
        // We are missing history; ask this peer to fill the gap.
        this.#requestHeaders(peer);
        return;

      case ACCEPT.CONNECTED:
        // Tell everyone else, and see whether an orphan now connects.
        this.net.broadcast(MSG.INV, { items: [{ type: INV_TYPE.BLOCK, hash }] }, peer);
        this.#drainOrphans();
        // A peer that had more may have more still.
        if (peer.chainWork > this.chain.chainWork) this.#requestHeaders(peer);
        return;

      default:
        return;
    }
  }

  #rememberOrphan(hash: Hex, block: Block): void {
    if (this.#orphans.size >= MAX_ORPHANS) {
      const oldest = this.#orphans.keys().next().value as Hex | undefined;
      if (oldest) this.#orphans.delete(oldest);
    }
    this.#orphans.set(hash, block);
  }

  /** Retry orphans whose parent has since arrived. Repeats until nothing moves. */
  #drainOrphans(): void {
    let progress = true;
    while (progress) {
      progress = false;
      for (const [hash, block] of [...this.#orphans]) {
        if (!this.chain.hasBlock(block.header.prevHash)) continue;
        this.#orphans.delete(hash);
        const res = this.submitBlock(block);
        if (res.status === ACCEPT.CONNECTED) {
          this.net.broadcast(MSG.INV, { items: [{ type: INV_TYPE.BLOCK, hash }] });
          progress = true;
        }
      }
    }
  }

  /**
   * Accept a block from any source, and keep the mempool consistent with the
   * resulting tip.
   */
  submitBlock(block: Block): AcceptResult {
    const before = this.chain.tipHash;
    const result = this.chain.acceptBlock(block);

    if (result.status !== ACCEPT.CONNECTED) return result;

    // Transactions from disconnected blocks go back into the pool; those in
    // connected blocks come out of it. Order matters: restore first, then
    // remove, so a transaction present in both branches ends up removed.
    if (result.reorg) {
      for (const hash of result.reorg.disconnected) {
        const disconnected = this.chain.getBlock(hash);
        if (disconnected) {
          this.mempool.onBlockDisconnected(
            disconnected.transactions,
            this.chain.state,
            this.chain.height,
            this.chain.tip.time,
          );
        }
      }
      for (const hash of result.reorg.connected) {
        const connected = this.chain.getBlock(hash);
        if (connected) this.mempool.onBlockConnected(connected.transactions);
      }
      this.emit('reorg', result.reorg);
    } else {
      this.mempool.onBlockConnected(block.transactions);
    }

    this.mempool.revalidate(this.chain.state, this.chain.height, this.chain.tip.time);
    this.emit('tip', { hash: this.chain.tipHash, height: this.chain.height, previous: before });
    return result;
  }

  /* ──────────────────────────────────────────────────── transactions ── */

  #onTx(tx: Transaction, peer: Peer): void {
    if (!tx?.kind || !Array.isArray(tx.inputs)) {
      peer.misbehave(20, 'malformed transaction');
      return;
    }
    let id: Hex;
    try {
      id = txid(tx);
    } catch {
      peer.misbehave(20, 'transaction could not be hashed');
      return;
    }
    this.#inFlight.delete(id);

    const result = this.submitTransaction(tx);
    if (!result.ok) {
      // A transaction can fail for benign reasons — it may simply have been
      // mined already. Score it lightly; only structural nonsense is punished.
      peer.misbehave(5, `rejected transaction ${id}: ${result.error}`);
      return;
    }
    if (!result.duplicate) {
      this.net.broadcast(MSG.INV, { items: [{ type: INV_TYPE.TX, hash: id }] }, peer);
    }
  }

  /** Admit a transaction to the mempool and announce it. */
  submitTransaction(tx: Transaction) {
    return this.mempool.add(tx, this.chain.state, this.chain.height, this.chain.tip.time + 1);
  }

  /** Announce a locally created transaction to every peer. */
  relayTransaction(tx: Transaction): number {
    return this.net.broadcast(MSG.INV, { items: [{ type: INV_TYPE.TX, hash: txid(tx) }] });
  }

  #onMempoolRequest(peer: Peer): void {
    const items = this.mempool
      .ids()
      .slice(0, MAX_INV_PER_MESSAGE)
      .map((hash) => ({ type: INV_TYPE.TX, hash }) as InvItem);
    if (items.length > 0) peer.send(MSG.INV, { items } satisfies InvPayload);
  }

  /* ────────────────────────────────────────────────────────── mining ── */

  /**
   * Mine one block on the current tip, drawing from the mempool.
   *
   * Single-threaded and blocking, which is honest for a reference node: it
   * exists to move a testnet along, not to compete for hash rate.
   */
  mineOne(minerAddress: string, opts: { time?: number; maxAttempts?: number } = {}) {
    const candidates = this.mempool.forBlock();
    const result = this.chain.mineBlock(candidates, minerAddress, opts);

    if (result.accepted.status === ACCEPT.CONNECTED) {
      this.mempool.onBlockConnected(result.block.transactions);
      this.mempool.revalidate(this.chain.state, this.chain.height, this.chain.tip.time);
      this.net.broadcast(MSG.INV, {
        items: [{ type: INV_TYPE.BLOCK, hash: blockHash(result.block.header) }],
      });
      this.emit('mined', { hash: blockHash(result.block.header), height: this.chain.height });
      this.emit('tip', { hash: this.chain.tipHash, height: this.chain.height });
    }
    return result;
  }

  /** Ask every peer for their mempool. Useful right after connecting. */
  requestMempools(): number {
    return this.net.broadcast(MSG.MEMPOOL, {});
  }

  /** Ask the best-known peer for headers. Used to kick a stalled sync. */
  syncFromBest(): boolean {
    const peer = this.net.bestPeer();
    if (!peer) return false;
    this.#requestHeaders(peer);
    return true;
  }
}
