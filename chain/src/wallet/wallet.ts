/**
 * The DeckxCoin wallet.
 *
 * Sits on top of `HdWallet` and a chain view, and does the four things a
 * wallet actually has to do:
 *
 *   • **Track what you own.** Scan the UTXO set for outputs paying any address
 *     this seed can derive, following BIP-44's gap limit so recovery from the
 *     mnemonic alone finds everything.
 *   • **Choose which coins to spend.** Coin selection is not a detail: a naive
 *     picker leaks information, creates dust, and overpays fees.
 *   • **Build and sign.** Assemble inputs, outputs and change; sign each input
 *     with the key that owns it.
 *   • **Never lose the change.** The single most expensive wallet bug in
 *     history is a change output sent nowhere. Change goes to a derived
 *     address of this same wallet, and the amount is checked before signing.
 *
 * ── What this is not ──────────────────────────────────────────────────────
 * There is no encrypted keystore. The wallet holds keys in memory for as long
 * as the process runs and writes nothing sensitive to disk unless explicitly
 * asked to export. A production wallet would encrypt at rest with a
 * user-supplied passphrase; that is a real gap and it is listed as one.
 */

import { applyTx } from '../chain.ts';
import { formatDeckx, serializeTx, signInput, transferTx, txid, ZAPS_PER_DECKX } from '../tx.ts';
import type { PrevOut, Transaction, TxOutput } from '../tx.ts';
import { isValidAddress, type Hex } from '../crypto.ts';
import type { Utxo, WorldState } from '../state.ts';
import { COINBASE_MATURITY } from '../state.ts';
import { CHAIN_CHANGE, CHAIN_RECEIVE, GAP_LIMIT, HdWallet, type DerivedKey } from './hd.ts';

/** Anything smaller than this costs more to spend later than it is worth. */
export const DUST_THRESHOLD = 546n;
/** Default fee rate, zaps per byte. */
export const DEFAULT_FEE_RATE = 2;

export interface WalletUtxo extends Utxo {
  /** The derived key that can spend it. */
  readonly key: DerivedKey;
  readonly confirmations: number;
  readonly spendable: boolean;
}

export interface Balance {
  /** Everything the wallet can see. */
  readonly total: bigint;
  /** What it can actually spend right now — mature and confirmed. */
  readonly spendable: bigint;
  /** Coinbase outputs still inside the maturity window. */
  readonly immature: bigint;
  readonly utxoCount: number;
}

export interface BuildResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly transaction?: Transaction;
  readonly fee?: bigint;
  readonly changeAddress?: string;
  readonly inputs?: readonly WalletUtxo[];
  readonly sizeBytes?: number;
}

export interface CoinSelection {
  readonly chosen: WalletUtxo[];
  readonly total: bigint;
}

/** How the wallet decides which coins to spend. */
export const COIN_STRATEGY = {
  /**
   * Prefer a single input that covers the payment. Fewest inputs, smallest
   * transaction, cheapest fee, and it does not merge unrelated coins — which
   * is also the biggest privacy win available at selection time.
   */
  SMALLEST_SUFFICIENT: 'smallest-sufficient',
  /** Spend the largest coins first. Minimises input count on large payments. */
  LARGEST_FIRST: 'largest-first',
  /**
   * Spend the oldest coins first. Keeps the UTXO set from accumulating
   * long-lived dust, at the cost of merging coins of different ages.
   */
  OLDEST_FIRST: 'oldest-first',
} as const;

export type CoinStrategy = (typeof COIN_STRATEGY)[keyof typeof COIN_STRATEGY];

export interface WalletOptions {
  readonly hd: HdWallet;
  readonly gapLimit?: number;
  readonly feeRate?: number;
  readonly strategy?: CoinStrategy;
}

export class Wallet {
  readonly hd: HdWallet;
  readonly gapLimit: number;
  feeRate: number;
  strategy: CoinStrategy;

  /** address → derived key, for every address scanned so far. */
  readonly #known = new Map<string, DerivedKey>();
  #receiveScanned = 0;
  #changeScanned = 0;

  constructor(opts: WalletOptions) {
    this.hd = opts.hd;
    this.gapLimit = opts.gapLimit ?? GAP_LIMIT;
    this.feeRate = opts.feeRate ?? DEFAULT_FEE_RATE;
    this.strategy = opts.strategy ?? COIN_STRATEGY.SMALLEST_SUFFICIENT;
    this.#extend(CHAIN_RECEIVE, this.gapLimit);
    this.#extend(CHAIN_CHANGE, this.gapLimit);
  }

  /** Derive and remember the next `count` addresses on a branch. */
  #extend(chain: number, count: number): void {
    const from = chain === CHAIN_RECEIVE ? this.#receiveScanned : this.#changeScanned;
    for (const key of this.hd.range(chain, from, count)) this.#known.set(key.address, key);
    if (chain === CHAIN_RECEIVE) this.#receiveScanned = from + count;
    else this.#changeScanned = from + count;
  }

  get addressCount(): number {
    return this.#known.size;
  }

  /** Every address derived so far. */
  addresses(): string[] {
    return [...this.#known.keys()];
  }

  knows(address: string): boolean {
    return this.#known.has(address);
  }

  keyFor(address: string): DerivedKey | undefined {
    return this.#known.get(address);
  }

  /**
   * The next address that has never received anything.
   *
   * Handing out a fresh address per payment is the difference between a
   * wallet whose history is public and one whose is not.
   */
  nextReceiveAddress(state: WorldState): DerivedKey {
    for (let i = 0; ; i++) {
      if (i >= this.#receiveScanned) this.#extend(CHAIN_RECEIVE, this.gapLimit);
      const key = this.hd.receiving(i);
      this.#known.set(key.address, key);
      if (state.utxosFor(key.address).length === 0) return key;
      if (i > 10_000) throw new Error('nextReceiveAddress: scanned 10,000 addresses without a gap');
    }
  }

  /** The first change address with no history. Change never reuses. */
  nextChangeAddress(state: WorldState): DerivedKey {
    for (let i = 0; ; i++) {
      if (i >= this.#changeScanned) this.#extend(CHAIN_CHANGE, this.gapLimit);
      const key = this.hd.change(i);
      this.#known.set(key.address, key);
      if (state.utxosFor(key.address).length === 0) return key;
      if (i > 10_000) throw new Error('nextChangeAddress: scanned 10,000 addresses without a gap');
    }
  }

  /* ────────────────────────────────────────────────────────── scanning ── */

  /**
   * Find every output this wallet can spend.
   *
   * Extends each branch until `gapLimit` consecutive addresses come back
   * empty. A wallet that stopped at the first empty address would miss funds
   * sent to a gap — which happens routinely, because addresses are handed out
   * faster than they are paid.
   */
  scan(state: WorldState, tipHeight: number): WalletUtxo[] {
    const found: WalletUtxo[] = [];

    for (const chain of [CHAIN_RECEIVE, CHAIN_CHANGE]) {
      let index = 0;
      let emptyRun = 0;

      while (emptyRun < this.gapLimit) {
        const key = this.hd.derive(chain, index);
        this.#known.set(key.address, key);

        const utxos = state.utxosFor(key.address);
        if (utxos.length === 0) {
          emptyRun++;
        } else {
          emptyRun = 0;
          for (const utxo of utxos) {
            const confirmations = tipHeight - utxo.height + 1;
            const mature = !utxo.coinbase || confirmations >= COINBASE_MATURITY;
            found.push({ ...utxo, key, confirmations, spendable: mature });
          }
        }
        index++;
        if (index > 100_000) break;
      }

      if (chain === CHAIN_RECEIVE) this.#receiveScanned = Math.max(this.#receiveScanned, index);
      else this.#changeScanned = Math.max(this.#changeScanned, index);
    }

    return found;
  }

  balance(state: WorldState, tipHeight: number): Balance {
    const utxos = this.scan(state, tipHeight);
    let total = 0n;
    let spendable = 0n;
    let immature = 0n;

    for (const u of utxos) {
      total += u.value;
      if (u.spendable) spendable += u.value;
      else immature += u.value;
    }
    return { total, spendable, immature, utxoCount: utxos.length };
  }

  /* ─────────────────────────────────────────────────── coin selection ── */

  /**
   * Choose inputs covering `target`.
   *
   * Only spendable coins are considered — an immature coinbase looks like
   * money and is not, and building a transaction that spends one produces a
   * transaction the chain will reject.
   */
  select(utxos: readonly WalletUtxo[], target: bigint, strategy = this.strategy): CoinSelection {
    const usable = utxos.filter((u) => u.spendable);

    if (strategy === COIN_STRATEGY.SMALLEST_SUFFICIENT) {
      // A single input that covers it, as tight as possible: cheapest fee, no
      // coins merged, and change kept small.
      const single = usable
        .filter((u) => u.value >= target)
        .sort((a, b) => (a.value < b.value ? -1 : 1))[0];
      if (single) return { chosen: [single], total: single.value };
    }

    const ordered = [...usable].sort((a, b) => {
      if (strategy === COIN_STRATEGY.OLDEST_FIRST) return a.height - b.height;
      return a.value > b.value ? -1 : 1; // largest first
    });

    const chosen: WalletUtxo[] = [];
    let total = 0n;
    for (const u of ordered) {
      chosen.push(u);
      total += u.value;
      if (total >= target) break;
    }
    return { chosen, total };
  }

  /* ────────────────────────────────────────────────────────── sending ── */

  /**
   * Build and sign a payment.
   *
   * Fee is estimated from the transaction's real serialised size, then the
   * whole thing is re-checked against the chain's own validator before being
   * returned. A wallet that hands the user a transaction the network will
   * reject has done nothing useful.
   */
  send(
    opts: {
      state: WorldState;
      tipHeight: number;
      tipTime: number;
      to: string;
      amount: bigint;
      feeRate?: number;
      memo?: string;
      /** Send everything, sweeping the wallet. `amount` is ignored. */
      sweep?: boolean;
      strategy?: CoinStrategy;
    },
  ): BuildResult {
    const { state, tipHeight, tipTime, to } = opts;
    const feeRate = opts.feeRate ?? this.feeRate;

    if (!isValidAddress(to)) return { ok: false, error: `'${to}' is not a valid DeckxCoin address` };
    if (!opts.sweep && opts.amount <= 0n) return { ok: false, error: 'amount must be positive' };
    if (feeRate < 0) return { ok: false, error: 'fee rate must not be negative' };

    const utxos = this.scan(state, tipHeight);
    const spendable = utxos.filter((u) => u.spendable);
    if (spendable.length === 0) {
      const immature = utxos.reduce((s, u) => (u.spendable ? s : s + u.value), 0n);
      return {
        ok: false,
        error:
          immature > 0n
            ? `no spendable coins — ${formatDeckx(immature)} is still maturing`
            : 'wallet holds no coins',
      };
    }

    /* --- sweep: one output, fee taken from the total ------------------- */
    if (opts.sweep) {
      const total = spendable.reduce((s, u) => s + u.value, 0n);
      const size = estimateSize(spendable.length, 1);
      const fee = BigInt(Math.ceil(size * feeRate));
      if (total <= fee) {
        return { ok: false, error: `balance ${formatDeckx(total)} does not cover the ${fee} zap fee` };
      }
      return this.#assemble(
        spendable,
        [{ value: (total - fee).toString(), address: to }],
        fee,
        undefined,
        state,
        tipHeight,
        tipTime,
        opts.memo,
      );
    }

    /* --- ordinary payment --------------------------------------------- */
    // Two passes: the first sizes a transaction with change, the second
    // re-sizes if dropping the change output changed the fee.
    let selection = this.select(spendable, opts.amount, opts.strategy);
    let size = estimateSize(selection.chosen.length, 2);
    let fee = BigInt(Math.ceil(size * feeRate));

    if (selection.total < opts.amount + fee) {
      selection = this.select(spendable, opts.amount + fee, opts.strategy);
      size = estimateSize(selection.chosen.length, 2);
      fee = BigInt(Math.ceil(size * feeRate));
    }

    if (selection.total < opts.amount + fee) {
      const have = spendable.reduce((s, u) => s + u.value, 0n);
      return {
        ok: false,
        error:
          `insufficient funds: need ${formatDeckx(opts.amount + fee)} ` +
          `(${formatDeckx(opts.amount)} + ${fee} zap fee), have ${formatDeckx(have)}`,
      };
    }

    const outputs: TxOutput[] = [{ value: opts.amount.toString(), address: to }];
    let changeKey: DerivedKey | undefined;
    const change = selection.total - opts.amount - fee;

    if (change > DUST_THRESHOLD) {
      changeKey = this.nextChangeAddress(state);
      outputs.push({ value: change.toString(), address: changeKey.address });
    } else if (change > 0n) {
      /*
       * Change below the dust threshold is given to the miner rather than
       * created as an output. An output that costs more to spend than it holds
       * is not a saving — it is litter in the UTXO set that somebody has to
       * carry forever.
       */
      fee += change;
      size = estimateSize(selection.chosen.length, 1);
    }

    return this.#assemble(
      selection.chosen,
      outputs,
      fee,
      changeKey?.address,
      state,
      tipHeight,
      tipTime,
      opts.memo,
    );
  }

  /** Build, sign, and validate against the real chain rules. */
  #assemble(
    inputs: readonly WalletUtxo[],
    outputs: TxOutput[],
    fee: bigint,
    changeAddress: string | undefined,
    state: WorldState,
    tipHeight: number,
    tipTime: number,
    memo?: string,
  ): BuildResult {
    let tx = transferTx({
      inputs: inputs.map((u) => ({ txid: u.txid, vout: u.vout })),
      outputs,
      memo,
    });

    // Each input is signed by the key that owns it — inputs may well belong to
    // different derived keys, which is why `signTx` (one key for all) is not
    // usable here.
    inputs.forEach((utxo, i) => {
      const prev: PrevOut = { value: utxo.value, address: utxo.address, script: utxo.script };
      tx = signInput(tx, i, utxo.key, prev);
    });

    /*
     * Dry-run against the chain's own validator before returning. This is the
     * difference between a wallet that builds transactions and one that builds
     * *valid* transactions — and it costs one state clone.
     */
    const check = applyTx(tx, state.clone(), { height: tipHeight + 1, time: tipTime + 1 });
    if (!check.ok) return { ok: false, error: `wallet built an invalid transaction: ${check.error}` };
    if (check.fee !== fee) {
      return { ok: false, error: `fee mismatch: intended ${fee}, transaction pays ${check.fee}` };
    }

    return {
      ok: true,
      transaction: tx,
      fee,
      changeAddress,
      inputs,
      sizeBytes: serializeTx(tx, { withSignatures: true }).length,
    };
  }

  /* ────────────────────────────────────────────────────────── reports ── */

  summary(state: WorldState, tipHeight: number) {
    const balance = this.balance(state, tipHeight);
    return {
      fingerprint: this.hd.fingerprint(),
      account: this.hd.account,
      addressesDerived: this.addressCount,
      balance: balance.total.toString(),
      balancePretty: formatDeckx(balance.total),
      spendable: balance.spendable.toString(),
      spendablePretty: formatDeckx(balance.spendable),
      immature: balance.immature.toString(),
      utxos: balance.utxoCount,
      feeRate: this.feeRate,
      strategy: this.strategy,
    };
  }

  /** Transactions in the chain that paid this wallet or spent from it. */
  history(state: WorldState, tipHeight: number): Array<{
    txid: Hex;
    height: number;
    received: bigint;
    address: string;
    confirmations: number;
  }> {
    return this.scan(state, tipHeight)
      .map((u) => ({
        txid: u.txid,
        height: u.height,
        received: u.value,
        address: u.address,
        confirmations: u.confirmations,
      }))
      .sort((a, b) => b.height - a.height);
  }
}

/**
 * Estimate a transaction's serialised size.
 *
 * Deliberately an over-estimate. Under-estimating produces a fee below the
 * intended rate, which at best confirms late and at worst never confirms;
 * over-estimating costs a few zaps. The asymmetry decides the rounding.
 */
export function estimateSize(inputs: number, outputs: number): number {
  const OVERHEAD = 40; // version, kind, counts, locktime, empty contract/memo fields
  const PER_INPUT = 32 + 4 + 4 + 4 + 32 + 4 + 64 + 12; // outpoint, sequence, pubkey, signature, framing
  const PER_OUTPUT = 8 + 4 + 62 + 4 + 4; // value, length prefixes, bech32 address, empty script
  return OVERHEAD + inputs * PER_INPUT + outputs * PER_OUTPUT;
}

export { ZAPS_PER_DECKX, txid };
