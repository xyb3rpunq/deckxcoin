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
  type KeyPair,
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
  PACKET_SIZE,
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

/** One delivered-but-unsettled payment, or part of one. */
interface HeldPart {
  readonly amount: bigint;
  readonly added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }>;
  readonly route: Route;
}

interface DeliveryResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly failedAt?: string;
  readonly forwards: ForwardEvent[];
  /** HTLCs left pending along the route. Empty when delivery failed. */
  readonly added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }>;
  /** Channel to avoid on the next attempt, when the failure named one. */
  readonly blameChannel?: bigint;
}

export interface PartResult {
  readonly amount: bigint;
  readonly ok: boolean;
  readonly error?: string;
  readonly failedAt?: string;
  readonly route?: Route;
}

export interface MultiPartResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly preimage?: Hex;
  /** Every part tried, successful or not, in the order they were attempted. */
  readonly parts: readonly PartResult[];
  readonly forwards: readonly ForwardEvent[];
  readonly amountSent?: bigint;
  readonly feesPaid?: bigint;
  /** How many parts the payment finally took. Zero on failure. */
  readonly partsUsed?: number;
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
    funderKey: KeyPair;
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
    fundingTx = signTx(fundingTx, funderKey, [prev]);

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

  /* ═════════════════════════════════════════════ multi-part payments ══ */

  /**
   * Pay an invoice by splitting it across several routes.
   *
   * ── What this solves ──────────────────────────────────────────────────
   * A channel's capacity is a ceiling on any single payment through it. A node
   * with five channels of 2 DECKX each holds 10 DECKX and, without this, cannot
   * send 3. The liquidity exists; it is merely in pieces. Splitting the payment
   * to match is the whole idea.
   *
   * ── The property that makes it safe ───────────────────────────────────
   * **The receiver must not reveal the preimage until every part has arrived.**
   *
   * The preimage is the receipt: releasing it settles whichever HTLCs are
   * outstanding and lets each of them be claimed. Release it after two parts of
   * three and the payer has bought a full receipt for two thirds of the price —
   * and the invoice is marked paid. So parts are *held*, not settled, and the
   * preimage is only revealed once the total is present.
   *
   * The converse matters as much: a set that never completes must release every
   * part. Held HTLCs are locked funds for the payer and locked liquidity for
   * every node in between, so a stalled payment that is not unwound is an
   * outage that spreads.
   *
   * ── What binds the parts together ─────────────────────────────────────
   * The payment hash, and the payment secret. The hash alone is not enough:
   * every node that forwarded a part knows it, and could send its own part to
   * the same destination. The secret is in the invoice and reaches only the
   * final hop, so a part carrying the wrong one is refused on arrival.
   */
  payInvoiceMultiPart(
    from: VoltNode,
    encoded: string,
    opts: {
      currentHeight: number;
      now?: number;
      /** Most parts to split into. More parts means more routes and more fees. */
      maxParts?: number;
    } = { currentHeight: 0 },
  ): MultiPartResult {
    const maxParts = Math.max(1, opts.maxParts ?? 5);

    let invoice: Invoice;
    try {
      invoice = decodeInvoice(encoded);
    } catch (err) {
      return { ok: false, error: `invoice decode failed: ${(err as Error).message}`, parts: [], forwards: [] };
    }

    const invoiceCheck = checkInvoice(invoice, opts.now);
    if (!invoiceCheck.ok) return { ok: false, error: invoiceCheck.error, parts: [], forwards: [] };
    if (!this.nodes.has(invoice.payee)) {
      return { ok: false, error: 'payee is not reachable on this network', parts: [], forwards: [] };
    }

    const total = invoice.amount;
    const held: HeldPart[] = [];
    const forwards: ForwardEvent[] = [];
    const parts: PartResult[] = [];
    const excluded = new Set<bigint>();

    let remaining = total;
    let attempts = 0;
    // Each part needs a route, and each failed route costs an attempt. The
    // ceiling stops a node with many tiny channels from searching forever.
    const attemptLimit = maxParts * 3;

    while (remaining > 0n && attempts < attemptLimit) {
      attempts++;

      /*
       * Ask for the whole remainder first. If a single route can carry it, that
       * is the cheapest answer — one HTLC, one set of fees, and no holding
       * period. Splitting is a fallback, not a strategy.
       */
      let route = this.graph.findRoute({
        source: from.id,
        destination: invoice.payee,
        amount: remaining,
        finalCltvDelta: invoice.minFinalCltv,
        currentHeight: opts.currentHeight,
        exclude: excluded,
      });

      let partAmount = remaining;

      if (!route) {
        // Halve until something fits. Binary search on the amount rather than
        // guessing a split up front: the sender cannot see anyone's balances,
        // so the only way to learn what a path will carry is to ask.
        let probe = remaining / 2n;
        while (probe > 0n && !route) {
          route = this.graph.findRoute({
            source: from.id,
            destination: invoice.payee,
            amount: probe,
            finalCltvDelta: invoice.minFinalCltv,
            currentHeight: opts.currentHeight,
            exclude: excluded,
          });
          if (route) {
            partAmount = probe;
            break;
          }
          probe /= 2n;
        }
      }

      if (!route) {
        return this.#abandonParts(
          held,
          parts,
          forwards,
          held.length === 0
            ? 'no route found for any amount'
            : `no route for the remaining ${remaining} zaps after ${held.length} part(s)`,
        );
      }

      if (parts.length >= maxParts) {
        return this.#abandonParts(
          held,
          parts,
          forwards,
          `would need more than ${maxParts} parts`,
        );
      }

      const delivered = this.#deliver(from, invoice, route, partAmount, total);
      forwards.push(...delivered.forwards);

      if (!delivered.ok) {
        parts.push({ amount: partAmount, ok: false, error: delivered.error, failedAt: delivered.failedAt });
        // The failed part has already unwound itself. Exclude the channel that
        // refused and try the remainder again — the others stay held.
        const failedHop = route.hops.find((h) => this.nodes.get(h.from)?.name === delivered.failedAt);
        if (failedHop) excluded.add(failedHop.shortChannelId);
        else if (delivered.blameChannel !== undefined) excluded.add(delivered.blameChannel);
        else {
          return this.#abandonParts(held, parts, forwards, delivered.error ?? 'part failed');
        }
        continue;
      }

      held.push({ amount: partAmount, added: delivered.added, route });
      parts.push({ amount: partAmount, ok: true, route });
      remaining -= partAmount;
    }

    if (remaining > 0n) {
      return this.#abandonParts(held, parts, forwards, `gave up with ${remaining} zaps unrouted`);
    }

    /* --- every part is held; now, and only now, settle --------------- */
    return this.#settleParts(this.node(invoice.payee), invoice, held, parts, forwards);
  }

  /**
   * Release every held part, in one step.
   *
   * The checks here are the receiver's, and they run before a single HTLC is
   * settled — because the first settlement publishes the preimage, and after
   * that there is no taking it back.
   */
  #settleParts(
    payee: VoltNode,
    invoice: Invoice,
    held: HeldPart[],
    parts: PartResult[],
    forwards: ForwardEvent[],
  ): MultiPartResult {
    const record = payee.invoices.get(invoice.paymentHash);
    if (!record) return this.#abandonParts(held, parts, forwards, 'payee does not recognise this payment hash');
    if (record.settled) return this.#abandonParts(held, parts, forwards, 'invoice already settled');
    if (!isReceiptFor(invoice, record.preimage)) {
      return this.#abandonParts(held, parts, forwards, 'payee preimage does not match invoice');
    }

    const arrived = held.reduce((sum, p) => sum + p.amount, 0n);
    if (arrived < invoice.amount) {
      // Unreachable through the loop above, which only reaches here at zero
      // remaining. Kept because it is the one invariant whose violation costs
      // the payee money, and an assertion that never fires is cheap.
      return this.#abandonParts(
        held,
        parts,
        forwards,
        `refusing to settle: ${arrived} of ${invoice.amount} arrived`,
      );
    }

    for (const part of held) {
      for (let i = part.added.length - 1; i >= 0; i--) {
        const { channel, htlc } = part.added[i];
        channel.settleHtlc(htlc.id, record.preimage);
      }
    }
    record.settled = true;

    const totalSent = held.reduce((sum, p) => sum + p.route.totalAmount, 0n);
    const totalFees = held.reduce((sum, p) => sum + p.route.totalFees, 0n);

    return {
      ok: true,
      preimage: record.preimage,
      parts,
      forwards,
      amountSent: totalSent,
      feesPaid: totalFees,
      partsUsed: held.length,
    };
  }

  /**
   * Fail every part that is still held.
   *
   * A part that has been delivered but not settled is money locked at the payer
   * and liquidity locked at every hop it crossed. Leaving those in place because
   * the payment "failed anyway" is how one bad payment becomes a stuck channel.
   */
  #abandonParts(
    held: HeldPart[],
    parts: PartResult[],
    forwards: ForwardEvent[],
    error: string,
  ): MultiPartResult {
    for (const part of held) {
      for (let i = part.added.length - 1; i >= 0; i--) {
        const { channel, htlc } = part.added[i];
        if (htlc.status === HTLC_STATUS.PENDING) channel.failHtlc(htlc.id, error);
      }
    }
    return { ok: false, error, parts, forwards, partsUsed: 0 };
  }

  /**
   * Single-part payment: deliver, then settle at once.
   *
   * The two halves are separate because a multi-part payment has to hold
   * between them — see `payInvoiceMultiPart`.
   */
  #attempt(from: VoltNode, invoice: Invoice, route: Route): PaymentResult {
    const delivered = this.#deliver(from, invoice, route, invoice.amount, invoice.amount);
    if (!delivered.ok) {
      return { ok: false, error: delivered.error, failedAt: delivered.failedAt, forwards: delivered.forwards };
    }
    return this.#settle(this.node(invoice.payee), invoice, delivered.added, route, delivered.forwards);
  }

  /**
   * Carry one payment (or one part of one) to the payee and stop there.
   *
   * Every HTLC along the way is added and left *pending*. Nothing is settled:
   * that requires the preimage, and releasing the preimage is a decision the
   * caller makes once it knows whether the whole payment has arrived.
   *
   * `partAmount` is what this delivery carries; `totalAmount` is what the
   * invoice is for. They are equal for an ordinary payment, and differ when the
   * payment was split — which is precisely what tells the payee to wait.
   */
  #deliver(
    from: VoltNode,
    invoice: Invoice,
    route: Route,
    partAmount: bigint,
    totalAmount: bigint,
  ): DeliveryResult {
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
      const final = next === undefined;
      return {
        shortChannelId: final ? 0n : next.shortChannelId,
        amountToForward: final ? hop.amountToForward : next.amountToForward,
        outgoingCltv: final ? hop.outgoingCltv : next.outgoingCltv,
        final,
        // Only the last hop is told the total and the secret. A forwarding node
        // that learned either would learn how much of a split it is carrying,
        // and that it is on the path to the payee.
        ...(final ? { totalAmount, paymentSecret: invoice.paymentSecret } : {}),
      };
    });

    const assoc = fromHex(invoice.paymentHash);
    const built = buildOnion(hopPubkeys, payloads, assoc);

    const forwards: ForwardEvent[] = [];
    const added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }> = [];
    let packet: OnionPacket | undefined = built.packet;
    let sender = from;
    let incomingAmount = route.totalAmount;
    let incomingCltv = route.totalCltv;

    const abort = (error: string, failedAt?: string, blameChannel?: bigint): DeliveryResult => {
      for (let i = added.length - 1; i >= 0; i--) {
        const { channel, htlc } = added[i];
        if (htlc.status === HTLC_STATUS.PENDING) channel.failHtlc(htlc.id, error);
      }
      return { ok: false, error, failedAt, forwards, added: [], blameChannel };
    };

    for (let i = 0; i < route.hops.length; i++) {
      const hop = route.hops[i];
      const receiver = this.node(hop.to);
      const nodeChannel = sender.channels.get(hop.shortChannelId);
      if (!nodeChannel) return abort(`no channel ${hop.shortChannelId} at ${sender.name}`, sender.name);

      const channel = nodeChannel.channel;
      if (channel.state !== CHANNEL_STATE.OPEN) {
        return abort(`channel ${channel.id} is ${channel.state}`, sender.name, hop.shortChannelId);
      }
      if (channel.spendable(nodeChannel.side) < incomingAmount) {
        return abort(
          `insufficient liquidity on ${channel.id}: have ${channel.spendable(nodeChannel.side)}, need ${incomingAmount}`,
          sender.name,
          hop.shortChannelId,
        );
      }

      const htlc = channel.addHtlc(nodeChannel.side, incomingAmount, invoice.paymentHash, incomingCltv);
      added.push({ channel, htlc, side: nodeChannel.side });

      if (!packet) return abort('onion exhausted before route end', receiver.name);
      let peeled;
      try {
        peeled = peelOnion(packet, receiver.party.key.privateKey, assoc);
      } catch (err) {
        return abort(`onion rejected at ${receiver.name}: ${(err as Error).message}`, receiver.name);
      }

      // A forwarding node must be paid: what it receives must exceed what it
      // is instructed to send on. Otherwise it is being asked to work for free
      // — or to lose money.
      if (!peeled.payload.final) {
        if (peeled.payload.amountToForward >= incomingAmount) {
          return abort(`fee insufficient at ${receiver.name}`, receiver.name);
        }
        if (peeled.payload.outgoingCltv >= incomingCltv) {
          return abort(`cltv delta insufficient at ${receiver.name}`, receiver.name);
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
          return abort(`onion says final at hop ${i} but route continues`, receiver.name);
        }
        /*
         * The payee's acceptance checks. All of them run before anything is
         * held, because a part that can never be settled should not tie up
         * liquidity while the rest of the payment is assembled.
         *
         * Note what the secret is compared against: the record the *payee*
         * kept when it issued the invoice — not the invoice the payer handed
         * over. Checking the onion against the payer's own copy would be
         * checking a claim against itself, and would accept any invoice a payer
         * chose to construct. The whole point is that only someone who read the
         * payee's invoice knows this value.
         */
        const issued = receiver.invoices.get(invoice.paymentHash);
        if (!issued) {
          return abort(`${receiver.name} does not recognise this payment hash`, receiver.name);
        }
        if (issued.settled) {
          // Refused on arrival rather than after the set assembles. Holding
          // parts for an invoice that is already paid locks liquidity across
          // every hop for a payment that can never complete.
          return abort(`invoice already settled at ${receiver.name}`, receiver.name);
        }
        if (peeled.payload.paymentSecret !== issued.invoice.paymentSecret) {
          return abort(`payment secret mismatch at ${receiver.name}`, receiver.name);
        }
        if (peeled.payload.totalAmount !== totalAmount) {
          return abort(
            `parts disagree on the total: this one says ${peeled.payload.totalAmount}, expected ${totalAmount}`,
            receiver.name,
          );
        }
        if (peeled.payload.amountToForward < partAmount) {
          return abort(
            `part underpaid: ${peeled.payload.amountToForward} < ${partAmount}`,
            receiver.name,
          );
        }
        return { ok: true, added, forwards };
      }

      incomingAmount = peeled.payload.amountToForward;
      incomingCltv = peeled.payload.outgoingCltv;
      packet = peeled.next;
      sender = receiver;
    }

    return abort('route ended without reaching the payee');
  }


  /** Reveal the preimage at the destination and settle every HTLC backwards. */
  #settle(
    payee: VoltNode,
    invoice: Invoice,
    added: Array<{ channel: VoltChannel; htlc: Htlc; side: 'a' | 'b' }>,
    route: Route,
    forwards: ForwardEvent[],
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
      onionSize: PACKET_SIZE,
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
