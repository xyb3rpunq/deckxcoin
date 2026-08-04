/**
 * Volt — pathfinding.
 *
 * Routing on a payment channel network is not routing on the internet. Two
 * differences drive the whole design:
 *
 *  1. **Fees depend on the amount, and the amount depends on the fees.** Each
 *     hop takes `base + amount·ppm`, so the amount hop *i* forwards depends on
 *     everything downstream of it. The search therefore runs *backwards* from
 *     the destination: at each step the amount is already known, because it is
 *     the amount the previously-considered hop must receive.
 *
 *  2. **Capacity is public, balance is not.** The graph knows a channel holds
 *     1 DECKX; it does not know whether that DECKX sits on the left or the
 *     right. A route can therefore fail on liquidity even when the graph says
 *     it should work, which is why `findRoutes` returns *ranked alternatives*
 *     rather than a single answer, and why the sender is expected to retry.
 *
 * Cost function: `fee + amount · riskFactor · cltvDelta`. The second term
 * prices the opportunity cost of funds being locked — a cheap route that locks
 * your money for a week is not cheap.
 */

import type { Hex } from '../crypto.ts';

/**
 * A hop toward a payee whose channels are not announced.
 *
 * A node that never announces its channels cannot be routed to: the graph
 * simply does not contain it. That is often deliberate — announcing a channel
 * publishes who you are connected to and roughly how much you have with them —
 * and it means every private node would be unpayable.
 *
 * A route hint is the payee telling the payer the last few edges itself,
 * inside the invoice. The payer splices them into its own graph for that one
 * search. It is a small privacy trade made by the person it affects: the payee
 * reveals one peer to whoever it hands the invoice to, rather than revealing
 * every peer to everybody, forever.
 */
export interface RouteHint {
  readonly shortChannelId: bigint;
  /** The node that can forward to the payee. */
  readonly from: Hex;
  readonly to: Hex;
  readonly baseFee: bigint;
  readonly feePpm: bigint;
  readonly cltvDelta: number;
  /**
   * What the payee claims can be pushed through. A hint is a claim, not a
   * proof — the payer finds out by trying.
   */
  readonly capacity: bigint;
}

export interface ChannelEdge {
  /** Compact channel identifier, as it appears in onion hop payloads. */
  readonly shortChannelId: bigint;
  readonly from: Hex;
  readonly to: Hex;
  /** Total channel capacity, zaps. Public. */
  readonly capacity: bigint;
  /** Flat fee per forward, zaps. */
  readonly baseFee: bigint;
  /** Proportional fee, parts per million. */
  readonly feeRatePpm: bigint;
  /** Extra CLTV this hop demands on its incoming HTLC. */
  readonly cltvDelta: number;
  /** Largest single HTLC this hop will forward. */
  readonly maxHtlc: bigint;
  readonly minHtlc: bigint;
  readonly disabled?: boolean;
}

export interface RouteHop {
  readonly shortChannelId: bigint;
  readonly from: Hex;
  readonly to: Hex;
  /** Amount this hop forwards onward. */
  readonly amountToForward: bigint;
  /** Fee this hop keeps. Zero for the final hop. */
  readonly fee: bigint;
  /** CLTV expiry on the HTLC this hop hands onward. */
  readonly outgoingCltv: number;
}

export interface Route {
  readonly hops: readonly RouteHop[];
  /** Amount the sender must lock, including all fees. */
  readonly totalAmount: bigint;
  readonly totalFees: bigint;
  /** CLTV expiry of the sender's outgoing HTLC. The worst-case lockup. */
  readonly totalCltv: number;
}

/** Fee hop `edge` charges for forwarding `amount`. */
export function edgeFee(edge: ChannelEdge, amount: bigint): bigint {
  return edge.baseFee + (amount * edge.feeRatePpm) / 1_000_000n;
}

/** Default risk factor: locked liquidity priced at roughly 15 ppm per block. */
export const DEFAULT_RISK_FACTOR = 15n;

export class ChannelGraph {
  readonly #edges = new Map<string, ChannelEdge>();
  readonly #out = new Map<Hex, ChannelEdge[]>();
  readonly #in = new Map<Hex, ChannelEdge[]>();

  addChannel(edge: ChannelEdge): void {
    const key = `${edge.shortChannelId}:${edge.from}`;
    this.#edges.set(key, edge);
    push(this.#out, edge.from, edge);
    push(this.#in, edge.to, edge);
  }

  /** Register both directions of a channel. Policies may differ per direction. */
  addBidirectional(
    shortChannelId: bigint,
    a: Hex,
    b: Hex,
    capacity: bigint,
    policy: Partial<Pick<ChannelEdge, 'baseFee' | 'feeRatePpm' | 'cltvDelta' | 'maxHtlc' | 'minHtlc'>> = {},
  ): void {
    const defaults = {
      baseFee: 1n,
      feeRatePpm: 100n,
      cltvDelta: 40,
      maxHtlc: capacity,
      minHtlc: 1n,
      ...policy,
    };
    this.addChannel({ shortChannelId, from: a, to: b, capacity, ...defaults });
    this.addChannel({ shortChannelId, from: b, to: a, capacity, ...defaults });
  }

  setDisabled(shortChannelId: bigint, from: Hex, disabled: boolean): void {
    const key = `${shortChannelId}:${from}`;
    const edge = this.#edges.get(key);
    if (edge) this.#edges.set(key, { ...edge, disabled });
  }

  incoming(node: Hex): ChannelEdge[] {
    return (this.#in.get(node) ?? []).filter((e) => !e.disabled);
  }

  outgoing(node: Hex): ChannelEdge[] {
    return (this.#out.get(node) ?? []).filter((e) => !e.disabled);
  }

  get nodeCount(): number {
    return new Set([...this.#out.keys(), ...this.#in.keys()]).size;
  }

  get channelCount(): number {
    return this.#edges.size / 2;
  }

  get totalCapacity(): bigint {
    let sum = 0n;
    const seen = new Set<bigint>();
    for (const e of this.#edges.values()) {
      if (seen.has(e.shortChannelId)) continue;
      seen.add(e.shortChannelId);
      sum += e.capacity;
    }
    return sum;
  }

  edges(): ChannelEdge[] {
    return [...this.#edges.values()];
  }

  /**
   * Cheapest route from `source` to `destination` for `amount`.
   *
   * Dijkstra run backwards from the destination. `amountAt[node]` is the
   * amount that must *arrive* at `node` for the payment to complete, so it
   * grows as the search moves back towards the sender and accumulates fees.
   */
  findRoute(opts: {
    source: Hex;
    destination: Hex;
    amount: bigint;
    finalCltvDelta: number;
    currentHeight: number;
    maxHops?: number;
    riskFactor?: bigint;
    /** Channels to avoid — the sender's record of what failed on the last attempt. */
    exclude?: ReadonlySet<bigint>;
    /**
     * Edges the payee supplied, valid for this search only.
     *
     * Not added to the graph: a hint is one payee's claim about its own
     * unannounced channel, and folding it into the shared view would let any
     * invoice write into every future route calculation.
     */
    hints?: readonly RouteHint[];
  }): Route | undefined {
    const {
      source,
      destination,
      amount,
      finalCltvDelta,
      currentHeight,
      maxHops = 20,
      riskFactor = DEFAULT_RISK_FACTOR,
      exclude = new Set<bigint>(),
      hints = [],
    } = opts;

    if (source === destination) return undefined;
    if (amount <= 0n) return undefined;

    // Indexed by destination, because the search runs backwards from the payee.
    const hintEdges = new Map<Hex, ChannelEdge[]>();
    for (const hint of hints) {
      const edge: ChannelEdge = {
        shortChannelId: hint.shortChannelId,
        from: hint.from,
        to: hint.to,
        capacity: hint.capacity,
        baseFee: hint.baseFee,
        feePpm: hint.feePpm,
        cltvDelta: hint.cltvDelta,
        minHtlc: 1n,
        maxHtlc: hint.capacity,
        disabled: false,
      };
      const list = hintEdges.get(hint.to) ?? [];
      list.push(edge);
      hintEdges.set(hint.to, list);
    }

    const dist = new Map<Hex, bigint>();
    const amountAt = new Map<Hex, bigint>();
    const cltvAt = new Map<Hex, number>();
    const hopsAt = new Map<Hex, number>();
    const nextEdge = new Map<Hex, ChannelEdge>();

    dist.set(destination, 0n);
    amountAt.set(destination, amount);
    cltvAt.set(destination, currentHeight + finalCltvDelta);
    hopsAt.set(destination, 0);

    const visited = new Set<Hex>();
    // Small networks: a linear scan beats a heap and keeps the code obvious.
    const frontier = new Set<Hex>([destination]);

    while (frontier.size > 0) {
      let current: Hex | undefined;
      let best: bigint | undefined;
      for (const node of frontier) {
        const d = dist.get(node)!;
        if (best === undefined || d < best) {
          best = d;
          current = node;
        }
      }
      if (current === undefined) break;
      frontier.delete(current);
      if (visited.has(current)) continue;
      visited.add(current);
      if (current === source) break;

      const hops = hopsAt.get(current)!;
      if (hops >= maxHops) continue;

      const amountToForward = amountAt.get(current)!;
      const outgoingCltv = cltvAt.get(current)!;

      /*
       * Hinted edges are searched alongside the announced ones, but they live
       * only for this call. They are the payee's claim about a channel nobody
       * else can see, and folding them into the graph would let any invoice
       * write into every future route calculation.
       */
      const hinted = hintEdges.get(current) ?? [];
      for (const edge of [...this.incoming(current), ...hinted]) {
        if (visited.has(edge.from)) continue;
        if (exclude.has(edge.shortChannelId)) continue;
        if (amountToForward > edge.maxHtlc) continue;
        if (amountToForward < edge.minHtlc) continue;
        if (amountToForward > edge.capacity) continue;

        // The sender pays no fee to its own first hop, so the edge leaving the
        // source is free. Every other hop charges.
        const fee = edge.from === source ? 0n : edgeFee(edge, amountToForward);
        const nextAmount = amountToForward + fee;
        const nextCltv = outgoingCltv + edge.cltvDelta;

        const timeCost = (nextAmount * riskFactor * BigInt(edge.cltvDelta)) / 1_000_000n;
        const candidate = dist.get(current)! + fee + timeCost;

        const known = dist.get(edge.from);
        if (known === undefined || candidate < known) {
          dist.set(edge.from, candidate);
          amountAt.set(edge.from, nextAmount);
          cltvAt.set(edge.from, nextCltv);
          hopsAt.set(edge.from, hops + 1);
          nextEdge.set(edge.from, edge);
          frontier.add(edge.from);
        }
      }
    }

    if (!nextEdge.has(source)) return undefined;

    /* --- walk forward, materialising the route ------------------------ */
    const hops: RouteHop[] = [];
    let node = source;
    while (node !== destination) {
      const edge = nextEdge.get(node);
      if (!edge) return undefined;
      const inbound = amountAt.get(node)!;
      const outbound = amountAt.get(edge.to)!;
      hops.push({
        shortChannelId: edge.shortChannelId,
        from: edge.from,
        to: edge.to,
        amountToForward: outbound,
        fee: inbound - outbound,
        outgoingCltv: cltvAt.get(edge.to)!,
      });
      node = edge.to;
      if (hops.length > maxHops) return undefined;
    }

    const totalAmount = amountAt.get(source)!;
    return {
      hops,
      totalAmount,
      totalFees: totalAmount - amount,
      /*
       * Expiry of the HTLC the *sender* offers, which is the first hop's
       * incoming expiry — not the source's own `cltvAt`. A channel's
       * cltv_delta is a requirement its owner places on its own incoming
       * HTLC before it will forward; the sender forwards nothing, so the
       * delta on its outgoing channel does not apply to it.
       */
      totalCltv: hops[0].outgoingCltv,
    };
  }

  /**
   * Up to `count` distinct routes, each excluding a channel used by the
   * previous one. Gives the sender something to retry with when a route fails
   * on liquidity it could not have known about.
   */
  findRoutes(
    opts: Parameters<ChannelGraph['findRoute']>[0] & { count?: number },
  ): Route[] {
    const { count = 3 } = opts;
    const routes: Route[] = [];
    const excluded = new Set<bigint>(opts.exclude ?? []);

    for (let i = 0; i < count; i++) {
      const route = this.findRoute({ ...opts, exclude: excluded });
      if (!route) break;
      routes.push(route);
      // Drop the priciest hop of this route so the next search must differ.
      const priciest = [...route.hops].sort((a, b) => (a.fee > b.fee ? -1 : 1))[0];
      if (!priciest) break;
      excluded.add(priciest.shortChannelId);
    }
    return routes;
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}
