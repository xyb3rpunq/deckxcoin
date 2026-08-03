/**
 * Volt — nodes, channel lifecycle, and end-to-end routed payments.
 *
 * This is where the pieces meet: an on-chain funding transaction creates a
 * 2-of-2 output, a `VoltChannel` tracks the off-chain states, `ChannelGraph`
 * finds a path, `onion` hides it, and HTLCs make the whole route atomic.
 *
 * The atomicity argument, because it is the point of the entire exercise:
 * every hop's incoming HTLC is locked to the *same* payment hash as its
 * outgoing one, with strictly more CLTV headroom. A hop can only claim its
 * incoming HTLC by revealing the preimage — which is exactly the secret its
 * downstream neighbour needed to claim the outgoing one. So either the
 * preimage propagates all the way back and every hop is paid, or it never
 * appears and every HTLC times out. There is no state where an intermediate
 * node is out of pocket, and no state where the payer pays without the payee
 * being paid.
 */

import {
  fromHex,
  hash160,
  toHex,
  addressFromHash160,
  beToBigInt,
  type Hex,
} from '../crypto.ts';
import type { Blockchain } from '../chain.ts';
import {
  signTx,
  transferTx,
  txid,
  type OutputScript,
  type PrevOut,
  type Transaction,
} from '../tx.ts';
import type { Utxo } from '../state.ts';
import {
  CHANNEL_STATE,
  CLTV_DELTA,
  HTLC_STATUS,
  makeParty,
  VoltChannel,
  type ChannelParty,
  type Htlc,
} from './channel.ts';
import { ChannelGraph, type Route } from './router.ts';
import {
  buildOnion,
  peelOnion,
  wrapFailure,
  unwrapFailure,
  type HopPayload,
  type OnionPacket,
} from './onion.ts';
import {
  checkInvoice,
  createInvoice,
  decodeInvoice,
  encodeInvoice,
  isReceiptFor,
  newPaymentSecret,
  paymentSecretFromSeed,
  type Invoice,
} from './invoice.ts';

/**
 * Address of a 2-of-2 funding output. Committing to the sorted key pair means
 * both parties derive the same address regardless of who initiated.
 */
export function fundingAddress(keyA: Hex, keyB: Hex): string {
  const [x, y] = [keyA, keyB].sort();
  return addressFromHash160(hash160(fromHex(x + y)));
}

export function fundingScript(keyA: Hex, keyB: Hex): OutputScript {
  const [x, y] = [keyA, keyB].sort();
  return { type: 'multisig2', keys: [x, y] as [Hex, Hex] };
}

/** Compact channel id: the first 8 bytes of the funding txid, mixed with the vout. */
export function shortChannelId(fundingTxid: Hex, vout: number): bigint {
  return (beToBigInt(fromHex(fundingTxid).subarray(0, 7)) << 8n) | BigInt(vout & 0xff);
}

export interface NodeChannel {
  readonly channel: VoltChannel;
  /** Which side of the channel this node is. */
  readonly side: 'a' | 'b';
  readonly peer: Hex;
  readonly shortChannelId: bigint;
}

export interface ForwardEvent {
  readonly node: string;
  readonly channel: bigint;
  readonly amountIn: bigint;
  readonly amountOut: bigint;
  readonly fee: bigint;
  readonly cltv: number;
}

export interface PaymentResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly preimage?: Hex;
  readonly route?: Route;
  readonly forwards: readonly ForwardEvent[];
  readonly amountSent?: bigint;
  readonly feesPaid?: bigint;
  /** Which hop rejected the payment, if any. Recovered from the onion failure. */
  readonly failedAt?: string;
  readonly onionSize?: number;
}

export class VoltNode {
  readonly party: ChannelParty;
  readonly channels = new Map<bigint, NodeChannel>();
  /** Invoices this node issued, by payment hash. */
  readonly invoices = new Map<Hex, { invoice: Invoice; preimage: Hex; settled: boolean }>();
  /** Preimages learned while forwarding, so a hop can settle its incoming HTLC. */
  readonly learned = new Map<Hex, Hex>();

  constructor(name: string, seed: string) {
    this.party = makeParty(name, seed);
  }

  get id(): Hex {
    return toHex(this.party.key.publicKey);
  }

  get name(): string {
    return this.party.name;
  }

  get address(): string {
    return this.party.key.address;
  }

  channelTo(peer: Hex): NodeChannel | undefined {
    return [...this.channels.values()].find((c) => c.peer === peer);
  }

  localBalance(scid: bigint): bigint {
    const c = this.channels.get(scid);
    if (!c) return 0n;
    return c.side === 'a' ? c.channel.balanceA : c.channel.balanceB;
  }

  totalLocalBalance(): bigint {
    return [...this.channels.keys()].reduce((s, scid) => s + this.localBalance(scid), 0n);
  }

  /** Issue an invoice. `seed` makes the preimage deterministic for tests. */
  invoice(amount: bigint, description: string, opts: { seed?: string; timestamp?: number } = {}): Invoice {
    const secret = opts.seed ? paymentSecretFromSeed(opts.seed) : newPaymentSecret();
    const invoice = createInvoice({
      payee: this.party.key,
      amount,
      paymentHash: secret.paymentHash,
      description,
      timestamp: opts.timestamp,
    });
    this.invoices.set(secret.paymentHash, { invoice, preimage: secret.preimage, settled: false });
    return invoice;
  }
}

export class VoltNetwork {
  readonly nodes = new Map<Hex, VoltNode>();
  readonly graph = new ChannelGraph();
  readonly channels = new Map<bigint, VoltChannel>();
  /** Funding transactions, so a caller can mine them into the chain. */
  readonly fundingTxs: Transaction[] = [];

  addNode(name: string, seed = `volt/${name}`): VoltNode {
    const node = new VoltNode(name, seed);
    this.nodes.set(node.id, node);
    return node;
  }

  node(id: Hex): VoltNode {
    const n = this.nodes.get(id);
    if (!n) throw new Error(`unknown node ${id}`);
    return n;
  }

  byName(name: string): VoltNode {
    const n = [...this.nodes.values()].find((x) => x.name === name);
    if (!n) throw new Error(`unknown node ${name}`);
    return n;
  }

  /* --------------------------------------------------------- channel open */

  /**
   * Open a channel by spending `funder`'s on-chain UTXO into a 2-of-2 output.
   *
   * Returns the funding transaction. The caller mines it — a channel is not
   * usable until its funding output is confirmed, and pretending otherwise is
   * how you build a system that loses money to a reorg.
   */
  openChannel(opts: {
    a: VoltNode;
    b: VoltNode;
    capacity: bigint;
    /** UTXO the funder spends. Must be owned by `a`'s key. */
    funding: Utxo;
    funderKey: { privateKey: Uint8Array; publicKey: Uint8Array; address: string };
    changeAddress?: string;
    feeZaps?: bigint;
    pushToB?: bigint;
    policy?: { baseFee?: bigint; feeRatePpm?: bigint; cltvDelta?: number };
  }): { fundingTx: Transaction; channel: VoltChannel; shortChannelId: bigint } {
    const { a, b, capacity, funding, funderKey } = opts;
    const feeZaps = opts.feeZaps ?? 1000n;
    const pushToB = opts.pushToB ?? 0n;

    if (pushToB > capacity) throw new Error('openChannel: pushToB exceeds capacity');
    if (funding.value < capacity + feeZaps) {
      throw new Error(`openChannel: funding utxo ${funding.value} < capacity+fee ${capacity + feeZaps}`);
    }

    const keyA = toHex(a.party.key.publicKey);
    const keyB = toHex(b.party.key.publicKey);
    const address = fundingAddress(keyA, keyB);
    const script = fundingScript(keyA, keyB);

    const change = funding.value - capacity - feeZaps;
    const outputs = [{ value: capacity.toString(), address, script }];
    if (change > 0n) {
      outputs.push({
        value: change.toString(),
        address: opts.changeAddress ?? funderKey.address,
      } as never);
    }

    let fundingTx = transferTx({
      inputs: [{ txid: funding.txid, vout: funding.vout }],
      outputs,
      memo: `volt:open:${a.name}-${b.name}`,
    });
    const prev: PrevOut = { value: funding.value, address: funding.address, script: funding.script };
    fundingTx = signTx(fundingTx, funderKey as never, [prev]);

    const ftxid = txid(fundingTx);
    const scid = shortChannelId(ftxid, 0);

    const channel = new VoltChannel({
      id: `${a.name}-${b.name}`,
      a: a.party,
      b: b.party,
      funding: { txid: ftxid, vout: 0, value: capacity, address, script },
      balanceA: capacity - pushToB,
      balanceB: pushToB,
    });

    a.channels.set(scid, { channel, side: 'a', peer: b.id, shortChannelId: scid });
    b.channels.set(scid, { channel, side: 'b', peer: a.id, shortChannelId: scid });
    this.channels.set(scid, channel);
    this.fundingTxs.push(fundingTx);

    this.graph.addBidirectional(scid, a.id, b.id, capacity, {
      baseFee: opts.policy?.baseFee ?? 1n,
      feeRatePpm: opts.policy?.feeRatePpm ?? 100n,
      cltvDelta: opts.policy?.cltvDelta ?? CLTV_DELTA,
    });

    return { fundingTx, channel, shortChannelId: scid };
  }

  /** Mark a channel live once its funding transaction is buried. */
  confirmChannel(scid: bigint): void {
    const channel = this.channels.get(scid);
    if (!channel) throw new Error(`confirmChannel: unknown channel ${scid}`);
    channel.state = CHANNEL_STATE.OPEN;
    channel.commit();
  }

  /** Confirm every channel whose funding transaction is in the chain. */
  confirmAll(chain?: Blockchain): void {
    for (const [scid, channel] of this.channels) {
      if (chain && !chain.state.hasUtxo(channel.funding.txid, channel.funding.vout)) continue;
      this.confirmChannel(scid);
    }
  }

  /* ------------------------------------------------------------ payments */

  /**
   * Pay an invoice from `from`.
   *
   * The full round trip: route → onion → HTLCs forward → preimage back →
   * settle. Every hop peels exactly one onion layer and learns only its own
   * instruction.
   */
  payInvoice(
    from: VoltNode,
    encoded: string,
    opts: { currentHeight: number; now?: number; maxAttempts?: number } = { currentHeight: 0 },
  ): PaymentResult {
    let invoice: Invoice;
    try {
      invoice = decodeInvoice(encoded);
    } catch (err) {
      return { ok: false, error: `invoice decode failed: ${(err as Error).message}`, forwards: [] };
    }

    const invoiceCheck = checkInvoice(invoice, opts.now);
    if (!invoiceCheck.ok) return { ok: false, error: invoiceCheck.error, forwards: [] };

    const destination = invoice.payee;
    if (!this.nodes.has(destination)) {
      return { ok: false, error: 'payee is not reachable on this network', forwards: [] };
    }

    const excluded = new Set<bigint>();
    const maxAttempts = opts.maxAttempts ?? 3;
    let lastError = 'no route found';

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const route = this.graph.findRoute({
        source: from.id,
        destination,
        amount: invoice.amount,
        finalCltvDelta: invoice.minFinalCltv,
        currentHeight: opts.currentHeight,
        exclude: excluded,
      });
      if (!route) return { ok: false, error: lastError, forwards: [] };

      const result = this.#attempt(from, invoice, route);
      if (result.ok) return result;

      lastError = result.error ?? 'attempt failed';
      // Exclude the channel that failed and try again — this is what a real
      // sender does, and why liquidity opacity is survivable.
      const failedHop = route.hops.find((h) => this.nodes.get(h.from)?.name === result.failedAt);
      if (failedHop) excluded.add(failedHop.shortChannelId);
      else break;
    }

    return { ok: false, error: lastError, forwards: [] };
  }

  #attempt(from: VoltNode, invoice: Invoice, route: Route): PaymentResult {
    /* --- build the onion --------------------------------------------- */
    const hopPubkeys: Hex[] = route.hops.map((h) => h.to);
    /*
     * Payload `i` is read by `hops[i].to`, and describes what *that* node must
     * send onward — i.e. the parameters of hop i+1, not of hop i. Getting this
     * off by one is the classic Lightning implementation bug: every hop then
     * believes it is entitled to the fee of the hop before it, and the route
     * fails at the second node with a cryptic "fee insufficient".
     */
    const payloads: HopPayload[] = route.hops.map((hop, i) => {
      const next = route.hops[i + 1];
      return {
        shortChannelId: next ? next.shortChannelId : 0n,
        amountToForward: next ? next.amountToForward : hop.amountToForward,
        outgoingCltv: next ? next.outgoingCltv : hop.outgoingCltv,
        final: next === undefined,
      };
    });

    const assoc = fromHex(invoice.paymentHash);
    const built = buildOnion(hopPubkeys, payloads, assoc);

    /* --- forward the HTLCs ------------------------------------------- */
    const forwards: ForwardEvent[] = [];
    const added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }> = [];
    let packet: OnionPacket | undefined = built.packet;
    let sender = from;
    let incomingAmount = route.totalAmount;
    let incomingCltv = route.totalCltv;

    for (let i = 0; i < route.hops.length; i++) {
      const hop = route.hops[i];
      const receiver = this.node(hop.to);
      const nodeChannel = sender.channels.get(hop.shortChannelId);
      if (!nodeChannel) {
        return this.#unwind(added, `no channel ${hop.shortChannelId} at ${sender.name}`, sender.name, forwards);
      }
      const channel = nodeChannel.channel;

      if (channel.state !== CHANNEL_STATE.OPEN) {
        return this.#unwind(added, `channel ${channel.id} is ${channel.state}`, sender.name, forwards);
      }
      if (channel.spendable(nodeChannel.side) < incomingAmount) {
        return this.#unwind(
          added,
          `insufficient liquidity on ${channel.id}: have ${channel.spendable(nodeChannel.side)}, need ${incomingAmount}`,
          sender.name,
          forwards,
        );
      }

      const htlc = channel.addHtlc(
        nodeChannel.side,
        incomingAmount,
        invoice.paymentHash,
        incomingCltv,
      );
      added.push({ channel, htlc, side: nodeChannel.side });

      /* --- receiver peels its layer ---------------------------------- */
      if (!packet) return this.#unwind(added, 'onion exhausted before route end', receiver.name, forwards);
      let peeled;
      try {
        peeled = peelOnion(packet, receiver.party.key.privateKey, assoc);
      } catch (err) {
        return this.#unwind(added, `onion rejected at ${receiver.name}: ${(err as Error).message}`, receiver.name, forwards);
      }

      // A forwarding node must be paid: what it receives must exceed what it
      // is instructed to send on. Otherwise it is being asked to work for free
      // — or to lose money.
      if (!peeled.payload.final) {
        if (peeled.payload.amountToForward >= incomingAmount) {
          return this.#unwind(added, `fee insufficient at ${receiver.name}`, receiver.name, forwards);
        }
        if (peeled.payload.outgoingCltv >= incomingCltv) {
          return this.#unwind(added, `cltv delta insufficient at ${receiver.name}`, receiver.name, forwards);
        }
      }

      forwards.push({
        node: receiver.name,
        channel: hop.shortChannelId,
        amountIn: incomingAmount,
        amountOut: peeled.payload.final ? 0n : peeled.payload.amountToForward,
        fee: peeled.payload.final ? 0n : incomingAmount - peeled.payload.amountToForward,
        cltv: incomingCltv,
      });

      if (peeled.payload.final) {
        if (i !== route.hops.length - 1) {
          return this.#unwind(added, `onion says final at hop ${i} but route continues`, receiver.name, forwards);
        }
        if (peeled.payload.amountToForward < invoice.amount) {
          return this.#unwind(added, `underpaid: ${peeled.payload.amountToForward} < ${invoice.amount}`, receiver.name, forwards);
        }
        return this.#settle(receiver, invoice, added, route, forwards, built.packet);
      }

      incomingAmount = peeled.payload.amountToForward;
      incomingCltv = peeled.payload.outgoingCltv;
      packet = peeled.next;
      sender = receiver;
    }

    return this.#unwind(added, 'route ended without reaching the payee', undefined, forwards);
  }

  /** Reveal the preimage at the destination and settle every HTLC backwards. */
  #settle(
    payee: VoltNode,
    invoice: Invoice,
    added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }>,
    route: Route,
    forwards: ForwardEvent[],
    onion: OnionPacket,
  ): PaymentResult {
    const record = payee.invoices.get(invoice.paymentHash);
    if (!record) {
      return this.#unwind(added, 'payee does not recognise this payment hash', payee.name, forwards);
    }
    if (record.settled) {
      return this.#unwind(added, 'invoice already settled', payee.name, forwards);
    }
    if (!isReceiptFor(invoice, record.preimage)) {
      return this.#unwind(added, 'payee preimage does not match invoice', payee.name, forwards);
    }

    // Backwards, exactly as the preimage propagates in reality.
    for (let i = added.length - 1; i >= 0; i--) {
      const { channel, htlc } = added[i];
      channel.settleHtlc(htlc.id, record.preimage);
    }
    record.settled = true;

    return {
      ok: true,
      preimage: record.preimage,
      route,
      forwards,
      amountSent: route.totalAmount,
      feesPaid: route.totalFees,
      onionSize: 1 + 33 + 1300 + 32,
      ...{ onion: undefined },
    };
  }

  /**
   * Fail every HTLC added so far, in reverse. This is the property that makes
   * a failed payment cost nothing: no hop keeps a partial amount, because no
   * hop ever had a claim without the preimage.
   */
  #unwind(
    added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }>,
    error: string,
    failedAt: string | undefined,
    forwards: ForwardEvent[],
  ): PaymentResult {
    for (let i = added.length - 1; i >= 0; i--) {
      const { channel, htlc } = added[i];
      if (htlc.status === HTLC_STATUS.PENDING) channel.failHtlc(htlc.id, error);
    }
    return { ok: false, error, failedAt, forwards };
  }

  /* -------------------------------------------------------------- reports */

  stats() {
    return {
      nodes: this.nodes.size,
      channels: this.channels.size,
      capacity: this.graph.totalCapacity.toString(),
      openChannels: [...this.channels.values()].filter((c) => c.state === CHANNEL_STATE.OPEN).length,
    };
  }
}

export { encodeInvoice, decodeInvoice, wrapFailure, unwrapFailure };
