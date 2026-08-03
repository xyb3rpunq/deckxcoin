/**
 * Volt — payment channels.
 *
 * The Lightning half of DeckxCoin. A channel is a 2-of-2 output on-chain plus
 * an unbounded number of off-chain states, only one of which is ever
 * broadcast. The chain sees two transactions — open and close — no matter
 * whether the parties exchanged three payments or three million.
 *
 * State machine, per Poon–Dryja:
 *
 *   OPENING   funding transaction built, not yet confirmed
 *   OPEN      both parties hold a signed commitment; payments flow
 *   CLOSING   cooperative close broadcast, or a commitment force-closed
 *   CLOSED    settled on-chain
 *
 * Each update produces a *pair* of asymmetric commitments — A's copy encumbers
 * A's own output with a CSV delay and a revocation key B can use; B's copy
 * does the mirror. That asymmetry is the whole trick: whoever broadcasts is
 * the one who waits, and the one who cheats loses everything.
 */

import {
  fromHex,
  keyPairFromSeed,
  sha256,
  toHex,
  type Hex,
  type KeyPair,
} from '../crypto.ts';
import {
  cosignInput,
  signInput,
  transferTx,
  txid,
  withPreimage,
  type OutputScript,
  type PrevOut,
  type Transaction,
  type TxOutput,
} from '../tx.ts';
import { revocationKeyPair, revocationPubkey, SecretChain } from './secrets.ts';

/** Blocks the broadcaster of a commitment must wait before sweeping its own output. */
export const DEFAULT_CSV_DELAY = 144; // ≈ 1 day at 10-minute blocks
/** Outputs below this are uneconomic to sweep and are burned to fees instead. */
export const DUST_LIMIT = 546n;
/** Extra CLTV headroom each hop demands, so it can react before the next hop expires. */
export const CLTV_DELTA = 40;

export const CHANNEL_STATE = {
  OPENING: 'opening',
  OPEN: 'open',
  CLOSING: 'closing',
  CLOSED: 'closed',
} as const;

export type ChannelState = (typeof CHANNEL_STATE)[keyof typeof CHANNEL_STATE];

export const HTLC_STATUS = {
  PENDING: 'pending',
  SETTLED: 'settled',
  FAILED: 'failed',
} as const;

export type HtlcStatus = (typeof HTLC_STATUS)[keyof typeof HTLC_STATUS];

export interface Htlc {
  readonly id: number;
  /** Which side is paying. 'a' or 'b'. */
  readonly offerer: 'a' | 'b';
  readonly amount: bigint;
  readonly paymentHash: Hex;
  /** Absolute block height after which the offerer can reclaim. */
  readonly expiry: number;
  status: HtlcStatus;
  preimage?: Hex;
}

export interface ChannelParty {
  readonly name: string;
  readonly key: KeyPair;
  /** Long-term base from which revocation keys are derived. Never leaves the node. */
  readonly revocationBase: KeyPair;
  readonly secrets: SecretChain;
}

export function makeParty(name: string, seed: string): ChannelParty {
  return {
    name,
    key: keyPairFromSeed(`${seed}/node`),
    revocationBase: keyPairFromSeed(`${seed}/revocation-base`),
    secrets: new SecretChain(`${seed}/commitments`),
  };
}

export interface FundingOutpoint {
  readonly txid: Hex;
  readonly vout: number;
  readonly value: bigint;
  readonly address: string;
  readonly script: OutputScript;
}

export interface CommitmentBundle {
  /** Commitment held by A — A's own output is delayed and revocable by B. */
  readonly forA: Transaction;
  /** Commitment held by B — mirror image. */
  readonly forB: Transaction;
  readonly number: number;
}

/**
 * A bidirectional payment channel between two parties.
 *
 * Both parties' key material lives in one object because this is a reference
 * implementation and a simulator, not a wallet. A production node would hold
 * only its own half and exchange signatures over the wire; every method here
 * is written so that split is a mechanical refactor, not a redesign.
 */
export class VoltChannel {
  readonly id: string;
  readonly a: ChannelParty;
  readonly b: ChannelParty;
  readonly capacity: bigint;
  readonly csvDelay: number;
  readonly funding: FundingOutpoint;

  balanceA: bigint;
  balanceB: bigint;
  state: ChannelState = CHANNEL_STATE.OPENING;
  commitmentNumber = 0;
  readonly htlcs: Htlc[] = [];
  #nextHtlcId = 0;

  /** Per-commitment secrets received from the counterparty, indexed by commitment number. */
  readonly revokedByA = new Map<number, Hex>();
  readonly revokedByB = new Map<number, Hex>();
  /** Every commitment ever built, so a test (or a watchtower) can replay an old one. */
  readonly history: CommitmentBundle[] = [];

  constructor(opts: {
    id: string;
    a: ChannelParty;
    b: ChannelParty;
    funding: FundingOutpoint;
    balanceA: bigint;
    balanceB: bigint;
    csvDelay?: number;
  }) {
    this.id = opts.id;
    this.a = opts.a;
    this.b = opts.b;
    this.funding = opts.funding;
    this.capacity = opts.funding.value;
    this.balanceA = opts.balanceA;
    this.balanceB = opts.balanceB;
    this.csvDelay = opts.csvDelay ?? DEFAULT_CSV_DELAY;

    if (this.balanceA + this.balanceB !== this.capacity) {
      throw new Error('VoltChannel: balances must sum to funding value');
    }
  }

  /** Value currently locked in in-flight HTLCs, per side. */
  pendingOut(side: 'a' | 'b'): bigint {
    return this.htlcs
      .filter((h) => h.offerer === side && h.status === HTLC_STATUS.PENDING)
      .reduce((s, h) => s + h.amount, 0n);
  }

  /** Spendable balance = balance − in-flight HTLCs offered by that side. */
  spendable(side: 'a' | 'b'): bigint {
    return (side === 'a' ? this.balanceA : this.balanceB) - this.pendingOut(side);
  }

  /* ------------------------------------------------------- commitments */

  #prevOut(): PrevOut {
    return {
      value: this.funding.value,
      address: this.funding.address,
      script: this.funding.script,
    };
  }

  /**
   * Build the commitment transaction held by `holder`.
   *
   * Outputs, in fixed order so both parties derive identical txids:
   *   0  to_holder   — revocable: CSV-delayed for the holder, sweepable
   *                    immediately by the counterparty's revocation key
   *   1  to_other    — plain, spendable at once (the non-broadcaster is not
   *                    punished for the other side going on-chain)
   *   2+ htlc        — one per in-flight payment, hash+timeout locked
   *
   * Dust outputs are dropped, exactly as BOLT-03 requires: an output that
   * costs more to sweep than it is worth is a griefing vector.
   */
  buildCommitment(holder: 'a' | 'b', commitmentNumber = this.commitmentNumber): Transaction {
    const owner = holder === 'a' ? this.a : this.b;
    const other = holder === 'a' ? this.b : this.a;
    const ownerBalance = holder === 'a' ? this.balanceA : this.balanceB;
    const otherBalance = holder === 'a' ? this.balanceB : this.balanceA;

    // Compressed points on both sides — see the note on `revocationPubkey`.
    const revKey = revocationPubkey(
      toHex(other.revocationBase.point),
      owner.secrets.point(commitmentNumber),
    );

    const outputs: TxOutput[] = [];

    const ownerAvailable = ownerBalance - this.pendingOut(holder);
    if (ownerAvailable >= DUST_LIMIT) {
      outputs.push({
        value: ownerAvailable.toString(),
        address: owner.key.address,
        script: { type: 'revocable', delay: this.csvDelay, revocationKey: revKey },
      });
    }

    const otherAvailable = otherBalance - this.pendingOut(holder === 'a' ? 'b' : 'a');
    if (otherAvailable >= DUST_LIMIT) {
      outputs.push({ value: otherAvailable.toString(), address: other.key.address });
    }

    for (const h of this.htlcs) {
      if (h.status !== HTLC_STATUS.PENDING) continue;
      if (h.amount < DUST_LIMIT) continue;
      const payee = h.offerer === 'a' ? this.b : this.a;
      const payer = h.offerer === 'a' ? this.a : this.b;
      outputs.push({
        value: h.amount.toString(),
        address: payee.key.address,
        script: {
          type: 'htlc',
          hash: h.paymentHash,
          timeout: h.expiry,
          refundKey: toHex(payer.key.publicKey),
        },
      });
    }

    if (outputs.length === 0) {
      throw new Error('buildCommitment: every output is dust — channel cannot be committed');
    }

    // Obscured commitment number in the sequence field: an observer who sees
    // one commitment on-chain learns the state index but nothing else.
    const obscured = 0x00800000 | (commitmentNumber & 0x0000ffff);

    let tx = transferTx({
      inputs: [{ txid: this.funding.txid, vout: this.funding.vout, sequence: obscured }],
      outputs,
      memo: `volt:${this.id}:${commitmentNumber}`,
    });

    // 2-of-2: both parties sign the identical digest.
    tx = signInput(tx, 0, this.a.key, this.#prevOut());
    tx = cosignInput(tx, 0, this.b.key, this.#prevOut());
    return tx;
  }

  /** Build and record the commitment pair for the current state. */
  commit(): CommitmentBundle {
    const bundle: CommitmentBundle = {
      forA: this.buildCommitment('a'),
      forB: this.buildCommitment('b'),
      number: this.commitmentNumber,
    };
    this.history[this.commitmentNumber] = bundle;
    return bundle;
  }

  /**
   * Advance to the next commitment, revoking the previous one.
   *
   * Revocation *is* the exchange of secrets. After this returns, each party
   * holds the material needed to punish the other for broadcasting state
   * `n-1`, and the old commitment is economically dead.
   */
  revokeAndAdvance(): { revokedNumber: number; secretFromA: Hex; secretFromB: Hex } {
    const revoked = this.commitmentNumber;
    const secretFromA = this.a.secrets.secretHex(revoked);
    const secretFromB = this.b.secrets.secretHex(revoked);
    // A hands its secret to B, and vice versa.
    this.revokedByA.set(revoked, secretFromA);
    this.revokedByB.set(revoked, secretFromB);
    this.commitmentNumber += 1;
    this.commit();
    return { revokedNumber: revoked, secretFromA, secretFromB };
  }

  /* ---------------------------------------------------------- payments */

  /**
   * Move `amount` from `from` to the other side, unconditionally.
   *
   * Direct channel payment: no HTLC, because there is no third party to be
   * trusted. Both commitments are rebuilt and the previous pair revoked.
   */
  pay(from: 'a' | 'b', amount: bigint): void {
    this.#assertOpen();
    if (amount <= 0n) throw new Error('pay: amount must be positive');
    if (this.spendable(from) < amount) {
      throw new Error(`pay: insufficient spendable balance (${this.spendable(from)} < ${amount})`);
    }
    if (from === 'a') {
      this.balanceA -= amount;
      this.balanceB += amount;
    } else {
      this.balanceB -= amount;
      this.balanceA += amount;
    }
    this.revokeAndAdvance();
  }

  /**
   * Offer an HTLC. The amount leaves the offerer's spendable balance
   * immediately but does not arrive until the preimage is revealed — that
   * suspension is exactly what makes a multi-hop route atomic.
   */
  addHtlc(offerer: 'a' | 'b', amount: bigint, paymentHash: Hex, expiry: number): Htlc {
    this.#assertOpen();
    if (amount <= 0n) throw new Error('addHtlc: amount must be positive');
    if (this.spendable(offerer) < amount) {
      throw new Error(`addHtlc: insufficient spendable balance (${this.spendable(offerer)} < ${amount})`);
    }
    const htlc: Htlc = {
      id: this.#nextHtlcId++,
      offerer,
      amount,
      paymentHash,
      expiry,
      status: HTLC_STATUS.PENDING,
    };
    this.htlcs.push(htlc);
    this.revokeAndAdvance();
    return htlc;
  }

  /** Settle an HTLC by revealing the preimage. Value moves to the payee. */
  settleHtlc(id: number, preimage: Hex): Htlc {
    const htlc = this.#htlc(id);
    if (htlc.status !== HTLC_STATUS.PENDING) throw new Error(`settleHtlc: htlc ${id} is ${htlc.status}`);
    if (toHex(sha256(fromHex(preimage))) !== htlc.paymentHash) {
      throw new Error('settleHtlc: preimage does not match payment hash');
    }
    if (htlc.offerer === 'a') {
      this.balanceA -= htlc.amount;
      this.balanceB += htlc.amount;
    } else {
      this.balanceB -= htlc.amount;
      this.balanceA += htlc.amount;
    }
    htlc.status = HTLC_STATUS.SETTLED;
    htlc.preimage = preimage;
    this.revokeAndAdvance();
    return htlc;
  }

  /** Fail an HTLC back. The suspended amount returns to the offerer. */
  failHtlc(id: number, reason = 'unspecified'): Htlc {
    const htlc = this.#htlc(id);
    if (htlc.status !== HTLC_STATUS.PENDING) throw new Error(`failHtlc: htlc ${id} is ${htlc.status}`);
    htlc.status = HTLC_STATUS.FAILED;
    void reason;
    this.revokeAndAdvance();
    return htlc;
  }

  #htlc(id: number): Htlc {
    const h = this.htlcs.find((x) => x.id === id);
    if (!h) throw new Error(`unknown htlc ${id}`);
    return h;
  }

  #assertOpen(): void {
    if (this.state !== CHANNEL_STATE.OPEN) {
      throw new Error(`channel ${this.id} is ${this.state}, expected open`);
    }
  }

  /* ------------------------------------------------------------ closing */

  /**
   * Cooperative close: a plain 2-of-2 spend paying each side its final
   * balance, with no timelocks and no revocation branches. Cheapest and
   * fastest outcome, and the one both parties want.
   */
  cooperativeClose(feeZaps = 1000n): Transaction {
    if (this.htlcs.some((h) => h.status === HTLC_STATUS.PENDING)) {
      throw new Error('cooperativeClose: cannot close with HTLCs in flight');
    }
    // The initiator pays the closing fee, as in BOLT-02.
    const outA = this.balanceA - feeZaps;
    const outB = this.balanceB;
    if (outA < 0n) throw new Error('cooperativeClose: initiator cannot cover the closing fee');

    const outputs: TxOutput[] = [];
    if (outA >= DUST_LIMIT) outputs.push({ value: outA.toString(), address: this.a.key.address });
    if (outB >= DUST_LIMIT) outputs.push({ value: outB.toString(), address: this.b.key.address });

    let tx = transferTx({
      inputs: [{ txid: this.funding.txid, vout: this.funding.vout }],
      outputs,
      memo: `volt:${this.id}:close`,
    });
    tx = signInput(tx, 0, this.a.key, this.#prevOut());
    tx = cosignInput(tx, 0, this.b.key, this.#prevOut());
    this.state = CHANNEL_STATE.CLOSING;
    return tx;
  }

  /** Force close: broadcast the latest commitment. Legitimate, just slower and dearer. */
  forceClose(by: 'a' | 'b'): Transaction {
    const tx = this.buildCommitment(by);
    this.state = CHANNEL_STATE.CLOSING;
    return tx;
  }

  /**
   * Build the penalty transaction that sweeps a revoked commitment.
   *
   * `victim` is the party that broadcast the stale state; the caller is the
   * one punishing them. The sweep takes *both* outputs — the cheater's
   * delayed output via the revocation key, and the punisher's own output
   * because it is theirs anyway.
   */
  penaltyFor(
    revokedCommitment: Transaction,
    revokedNumber: number,
    cheater: 'a' | 'b',
    sweepTo: string,
    feeZaps = 1000n,
  ): Transaction {
    const victimParty = cheater === 'a' ? this.a : this.b;
    const punisher = cheater === 'a' ? this.b : this.a;

    const perCommitmentSecret = victimParty.secrets.secret(revokedNumber);
    const revKey = revocationKeyPair(punisher.revocationBase.privateKey, perCommitmentSecret);

    const commitId = txid(revokedCommitment);
    const inputs: Array<{ txid: Hex; vout: number; sequence?: number }> = [];
    const prevOuts: PrevOut[] = [];
    const signers: KeyPair[] = [];
    let total = 0n;

    revokedCommitment.outputs.forEach((out, vout) => {
      const value = BigInt(out.value);
      if (out.script?.type === 'revocable') {
        // The cheater's own output — swept immediately with the revocation key.
        inputs.push({ txid: commitId, vout, sequence: 0xffffffff });
        prevOuts.push({ value, address: out.address, script: out.script });
        signers.push(revKey);
        total += value;
      } else if (out.address === punisher.key.address && !out.script) {
        // The punisher's plain output — already theirs, swept in the same tx.
        inputs.push({ txid: commitId, vout, sequence: 0xffffffff });
        prevOuts.push({ value, address: out.address });
        signers.push(punisher.key);
        total += value;
      }
    });

    if (inputs.length === 0) throw new Error('penaltyFor: nothing to sweep');
    if (total <= feeZaps) throw new Error('penaltyFor: sweep value below fee');

    let tx = transferTx({
      inputs,
      outputs: [{ value: (total - feeZaps).toString(), address: sweepTo }],
      memo: `volt:${this.id}:penalty:${revokedNumber}`,
    });
    signers.forEach((signer, i) => {
      tx = signInput(tx, i, signer, prevOuts[i]);
    });
    return tx;
  }

  /**
   * Sweep an HTLC output from a broadcast commitment by revealing the
   * preimage. This is the on-chain fallback when a counterparty goes silent
   * mid-route — the payment still completes, it just costs a chain fee.
   */
  sweepHtlcWithPreimage(
    commitment: Transaction,
    htlcIndex: number,
    preimage: Hex,
    payee: 'a' | 'b',
    feeZaps = 500n,
  ): Transaction {
    const out = commitment.outputs[htlcIndex];
    if (out?.script?.type !== 'htlc') throw new Error('sweepHtlcWithPreimage: not an htlc output');
    const value = BigInt(out.value);
    if (value <= feeZaps) throw new Error('sweepHtlcWithPreimage: value below fee');
    const key = payee === 'a' ? this.a.key : this.b.key;

    let tx = transferTx({
      inputs: [{ txid: txid(commitment), vout: htlcIndex }],
      outputs: [{ value: (value - feeZaps).toString(), address: key.address }],
      memo: `volt:${this.id}:htlc-claim`,
    });
    tx = withPreimage(tx, 0, preimage);
    tx = signInput(tx, 0, key, { value, address: out.address, script: out.script });
    return tx;
  }

  /** Reclaim an expired HTLC after its timeout. The refund branch. */
  refundHtlc(
    commitment: Transaction,
    htlcIndex: number,
    payer: 'a' | 'b',
    atHeight: number,
    feeZaps = 500n,
  ): Transaction {
    const out = commitment.outputs[htlcIndex];
    if (out?.script?.type !== 'htlc') throw new Error('refundHtlc: not an htlc output');
    const value = BigInt(out.value);
    const key = payer === 'a' ? this.a.key : this.b.key;

    let tx = transferTx({
      inputs: [{ txid: txid(commitment), vout: htlcIndex }],
      outputs: [{ value: (value - feeZaps).toString(), address: key.address }],
      lockTime: Math.max(atHeight, out.script.timeout),
      memo: `volt:${this.id}:htlc-refund`,
    });
    tx = signInput(tx, 0, key, { value, address: out.address, script: out.script });
    return tx;
  }

  /* ------------------------------------------------------------ reports */

  summary() {
    return {
      id: this.id,
      state: this.state,
      capacity: this.capacity.toString(),
      balanceA: this.balanceA.toString(),
      balanceB: this.balanceB.toString(),
      commitmentNumber: this.commitmentNumber,
      htlcsPending: this.htlcs.filter((h) => h.status === HTLC_STATUS.PENDING).length,
      htlcsSettled: this.htlcs.filter((h) => h.status === HTLC_STATUS.SETTLED).length,
      revocations: this.revokedByA.size,
    };
  }
}
