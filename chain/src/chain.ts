/**
 * The chain: block assembly, validation, and state transition.
 *
 * `Blockchain` owns the canonical block list and the world state. It is the
 * only place where a block is allowed to mutate state, and it does so
 * transactionally: a block is applied to a *clone* of the state, and the clone
 * is promoted only if every transaction in it validated. A half-applied block
 * can never be observed.
 *
 * Fork choice is most-accumulated-work, not longest — the distinction matters
 * the moment difficulty changes, and getting it wrong is how a chain gets
 * reorganised by a cheap low-difficulty branch.
 */

import {
  BLOCK_GAS_LIMIT,
  blockHash,
  blockSubsidy,
  blockWork,
  checkHeader,
  computeMerkleRoot,
  cumulativeIssuance,
  GENESIS_BITS,
  GENESIS_MEMO,
  MAX_SUPPLY,
  mine,
  nextBits,
  RETARGET_INTERVAL,
  type Block,
  type BlockHeader,
} from './block.ts';
import { contractAddress, isContractAddress, keyPairFromSeed, type Hex } from './crypto.ts';
import { EMPTY_ROOT } from './merkle.ts';
import { COINBASE_MATURITY, WorldState, type Utxo } from './state.ts';
import {
  checkTx,
  coinbaseTx,
  txid,
  TX_KIND,
  type PrevOut,
  type Transaction,
} from './tx.ts';
import { addressWord, execute, type VmLog, type VmResult } from './vm.ts';
import { fromHex } from './crypto.ts';

export interface ApplyResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly fee: bigint;
  readonly gasUsed: number;
  readonly logs: readonly VmLog[];
  readonly contractAddress?: string;
  readonly vm?: VmResult;
}

export interface AddBlockResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly hash?: Hex;
  readonly height?: number;
  readonly totalFees?: bigint;
  readonly gasUsed?: number;
}

/** Fixed genesis timestamp — 2026-08-02T00:00:00Z. Genesis must be reproducible byte-for-byte. */
export const GENESIS_TIME = 1_785_628_800;
/** Seed for the genesis coinbase recipient. Public on purpose: this is a reference chain. */
export const GENESIS_SEED = 'deckxcoin/genesis/rekt';
/** Regtest difficulty: effectively every hash wins. Consensus rules stay identical. */
export const REGTEST_BITS = 0x207fffff;

export class Blockchain {
  readonly blocks: Block[] = [];
  state = new WorldState();
  #work = 0n;
  /** Contract logs by block height, for the explorer. */
  readonly logsByHeight = new Map<number, VmLog[]>();

  get height(): number {
    return this.blocks.length - 1;
  }

  get tip(): Block {
    const t = this.blocks[this.blocks.length - 1];
    if (!t) throw new Error('chain is empty — call Blockchain.create() first');
    return t;
  }

  get tipHash(): Hex {
    return blockHash(this.tip.header);
  }

  /** Total accumulated proof of work. The fork-choice metric. */
  get chainWork(): bigint {
    return this.#work;
  }

  blockAt(height: number): Block | undefined {
    return this.blocks[height];
  }

  findBlockByHash(hash: Hex): Block | undefined {
    return this.blocks.find((b) => blockHash(b.header) === hash);
  }

  findTransaction(id: Hex): { tx: Transaction; height: number; index: number } | undefined {
    for (let h = 0; h < this.blocks.length; h++) {
      const idx = this.blocks[h].transactions.findIndex((t) => txid(t) === id);
      if (idx >= 0) return { tx: this.blocks[h].transactions[idx], height: h, index: idx };
    }
    return undefined;
  }

  /* ---------------------------------------------------------- genesis */

  /**
   * Build and mine the genesis block.
   *
   * Genesis is special-cased in every chain that exists, and the honest reason
   * is that it has no parent to validate against. What it must still satisfy:
   * real proof of work over a real header, a coinbase whose value equals the
   * subsidy, and a state root that matches the UTXO it creates. All three are
   * checked here and re-checked by the test suite.
   */
  static create(opts: { bits?: number; time?: number; seed?: string; memo?: string } = {}): Blockchain {
    const chain = new Blockchain();
    const miner = keyPairFromSeed(opts.seed ?? GENESIS_SEED);
    const bits = opts.bits ?? GENESIS_BITS;
    const time = opts.time ?? GENESIS_TIME;

    const cb = coinbaseTx(miner.address, blockSubsidy(0), 0, opts.memo ?? GENESIS_MEMO);

    // The state after genesis is exactly one coinbase UTXO.
    const state = new WorldState();
    state.addUtxo({
      txid: txid(cb),
      vout: 0,
      value: blockSubsidy(0),
      address: miner.address,
      height: 0,
      coinbase: true,
    });

    const template: BlockHeader = {
      version: 1,
      prevHash: EMPTY_ROOT,
      merkleRoot: computeMerkleRoot([cb]),
      stateRoot: state.stateRoot(),
      time,
      bits,
      height: 0,
      nonce: 0,
      extraNonce: 0,
    };

    const mined = mine(template);
    chain.blocks.push({ header: mined.header, transactions: [cb] });
    chain.state = state;
    chain.#work = blockWork(mined.header.bits);
    return chain;
  }

  /**
   * A local chain with trivial difficulty. Same rules, same validation, same
   * code paths — only the work target differs, so tests exercise consensus
   * without burning CPU on it. Bitcoin calls this regtest; so do we.
   */
  static regtest(seed = 'deckxcoin/regtest'): Blockchain {
    return Blockchain.create({ bits: REGTEST_BITS, seed, memo: 'REKT regtest' });
  }

  /** The keypair that owns the genesis coinbase. Deterministic, documented, public. */
  static genesisKey() {
    return keyPairFromSeed(GENESIS_SEED);
  }

  /* ------------------------------------------------- state transition */

  /**
   * Apply one transaction to `state`. Mutates `state` on success only —
   * callers pass a clone so a rejected transaction leaves nothing behind.
   */
  applyTransaction(
    tx: Transaction,
    state: WorldState,
    ctx: { height: number; time: number; availableFees?: bigint },
  ): ApplyResult {
    /* --- coinbase ---------------------------------------------------- */
    if (tx.kind === TX_KIND.COINBASE) {
      const check = checkTx(tx, []);
      if (!check.ok) return failure(check.error!);

      const paid = tx.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
      const allowed = blockSubsidy(ctx.height) + (ctx.availableFees ?? 0n);
      if (paid > allowed) {
        return failure(`coinbase pays ${paid}, maximum allowed ${allowed}`);
      }

      /*
       * Hard cap, enforced as a consensus rule rather than left as a property
       * of the halving arithmetic.
       *
       * The geometric series already lands 0.0103 DECKX under 21,000,000 (see
       * `block.ts`), so this check should never fire. That is exactly why it is
       * here: a supply bug that only manifests after a decade of blocks is
       * worth two lines of belt-and-braces. Fees are excluded from the cap —
       * they are recycled coins, not new issuance.
       */
      const issuedBefore = cumulativeIssuance(ctx.height - 1);
      const newIssuance = paid - (ctx.availableFees ?? 0n);
      if (newIssuance > 0n && issuedBefore + newIssuance > MAX_SUPPLY) {
        return failure(
          `coinbase would push supply past the ${MAX_SUPPLY} zap cap ` +
            `(issued ${issuedBefore}, minting ${newIssuance})`,
        );
      }
      const id = txid(tx);
      tx.outputs.forEach((o, vout) => {
        state.addUtxo({
          txid: id,
          vout,
          value: BigInt(o.value),
          address: o.address,
          script: o.script,
          height: ctx.height,
          coinbase: true,
        });
      });
      return { ok: true, fee: 0n, gasUsed: 0, logs: [] };
    }

    /* --- resolve prevouts -------------------------------------------- */
    const prevUtxos: Utxo[] = [];
    for (const input of tx.inputs) {
      const u = state.getUtxo(input.txid, input.vout);
      if (!u) return failure(`input spends unknown or already-spent output ${input.txid}:${input.vout}`);
      if (u.coinbase && ctx.height - u.height < COINBASE_MATURITY) {
        return failure(
          `coinbase output ${input.txid}:${input.vout} is immature (${ctx.height - u.height}/${COINBASE_MATURITY})`,
        );
      }
      prevUtxos.push(u);
    }

    const prevOuts: PrevOut[] = prevUtxos.map((u) => ({
      value: u.value,
      address: u.address,
      script: u.script,
    }));

    const check = checkTx(tx, prevOuts);
    if (!check.ok) return failure(check.error!);
    const fee = check.fee;

    /* --- relative locktime (BIP-68) ----------------------------------- */
    for (let i = 0; i < tx.inputs.length; i++) {
      const seq = tx.inputs[i].sequence;
      if (seq !== 0xffffffff) {
        const minAge = seq & 0x0000ffff;
        const age = ctx.height - prevUtxos[i].height;
        if (age < minAge) {
          return failure(`input ${i}: relative timelock not met (age ${age} < ${minAge})`);
        }
      }
    }
    if (tx.lockTime > 0 && tx.kind !== TX_KIND.COINBASE && ctx.height < tx.lockTime) {
      return failure(`absolute locktime not met (height ${ctx.height} < ${tx.lockTime})`);
    }

    /* --- contract execution ------------------------------------------ */
    let vm: VmResult | undefined;
    let deployed: string | undefined;
    let gasUsed = 0;

    if (tx.kind === TX_KIND.DEPLOY || tx.kind === TX_KIND.CALL) {
      const payload = tx.contract!;
      const gasPrice = BigInt(payload.gasPrice);

      /*
       * Who is the CALLER?
       *
       * Not simply input 0 — on a covenant spend, input 0 is the
       * contract-locked output, so naming it the caller would make every
       * contract see *itself* as its own caller. `OP.CALLER` would then be
       * useless for authorisation, and any contract gating on identity
       * (escrow, multisig) would silently mis-authorise.
       *
       * The caller is the first input unlocked by a *key* — whoever actually
       * signed for this transaction and is paying its fee.
       */
      const spender =
        prevUtxos.find((u) => !isContractAddress(u.address))?.address ??
        prevUtxos[0]?.address ??
        '';

      const target =
        tx.kind === TX_KIND.DEPLOY
          ? contractAddress(spender, payload.nonce)
          : payload.target!;

      if (tx.kind === TX_KIND.DEPLOY) {
        if (state.getContract(target)) return failure(`contract already exists at ${target}`);
        if (state.nonceOf(spender) !== payload.nonce) {
          return failure(`deploy nonce mismatch: expected ${state.nonceOf(spender)}, got ${payload.nonce}`);
        }
      }

      const account = tx.kind === TX_KIND.CALL ? state.getContract(target) : undefined;
      if (tx.kind === TX_KIND.CALL && !account) return failure(`no contract at ${target}`);

      const code = tx.kind === TX_KIND.DEPLOY ? fromHex(payload.code!) : fromHex(account!.code);

      // Value being placed under the contract's control by this transaction:
      // outputs paid to the contract's own address. They stay ordinary UTXOs,
      // locked by code instead of by a key.
      const callValue = tx.outputs
        .filter((o) => o.address === target)
        .reduce((s, o) => s + BigInt(o.value), 0n);

      vm = execute(
        code,
        {
          address: target,
          caller: spender,
          callValue,
          calldata: payload.calldata.map((w) => BigInt(w)),
          blockNumber: ctx.height,
          blockTime: ctx.time,
          gasLimit: payload.gasLimit,
          balanceOf: (a) => state.balanceOf(a),
        },
        tx.kind === TX_KIND.CALL ? account!.storage : {},
      );

      gasUsed = vm.gasUsed;

      // Post-execution fee check: the fee must actually cover the gas burned.
      // The upfront gasLimit*gasPrice check in checkTx is the reservation;
      // this is the settlement. Unused reservation stays with the miner as a
      // tip — DeckxCoin has no refund output, by design (see docs/DESIGN.md).
      if (BigInt(gasUsed) * gasPrice > fee) {
        return failure(`fee ${fee} does not cover gasUsed*gasPrice ${BigInt(gasUsed) * gasPrice}`);
      }

      if (!vm.ok) {
        return { ok: false, error: `contract execution failed: ${vm.error}`, fee, gasUsed, logs: [], vm };
      }

      /* --- covenant authorisation ------------------------------------ */
      // Any input spending a contract-locked output requires the contract to
      // have returned a non-zero first word for THIS transaction.
      const spendsCovenant = prevUtxos.some((u) => isContractAddress(u.address));
      if (spendsCovenant) {
        const approved = vm.returnValue.length > 0 && BigInt(vm.returnValue[0]) !== 0n;
        if (!approved) return failure('covenant refused: contract did not authorise this spend', fee);
        // Bind the authorisation to the recipient so a valid approval cannot be
        // replayed by a third party redirecting the funds.
        const declared = vm.returnValue.length > 1 ? BigInt(vm.returnValue[1]) : 0n;
        if (declared !== 0n) {
          const matched = tx.outputs.some((o) => addressWord(o.address) === declared);
          if (!matched) return failure('covenant refused: no output matches the authorised recipient', fee);
        }
      }

      if (tx.kind === TX_KIND.DEPLOY) {
        state.putContract({
          address: target,
          code: payload.code!,
          storage: vm.storage,
          deployedAt: ctx.height,
          deployer: spender,
        });
        state.bumpNonce(spender);
        deployed = target;
      } else {
        state.setStorage(target, vm.storage);
      }
    }

    /* --- move the coins ---------------------------------------------- */
    for (const input of tx.inputs) state.spendUtxo(input.txid, input.vout);

    const id = txid(tx);
    tx.outputs.forEach((o, vout) => {
      state.addUtxo({
        txid: id,
        vout,
        value: BigInt(o.value),
        address: o.address,
        script: o.script,
        height: ctx.height,
        coinbase: false,
      });
    });

    return { ok: true, fee, gasUsed, logs: vm?.logs ?? [], contractAddress: deployed, vm };
  }

  /* ------------------------------------------------------- block intake */

  /**
   * Validate and append a block. All-or-nothing: state is only promoted if
   * every transaction applies cleanly and the resulting state root matches
   * the header's commitment.
   */
  addBlock(block: Block, now: number = Math.floor(Date.now() / 1000)): AddBlockResult {
    const headerCheck = checkHeader(block, now);
    if (!headerCheck.ok) return { ok: false, error: headerCheck.error };

    const { header } = block;
    if (header.height !== this.height + 1) {
      return { ok: false, error: `height must be ${this.height + 1}, got ${header.height}` };
    }
    if (header.prevHash !== this.tipHash) {
      return { ok: false, error: `prevHash does not extend the tip (${this.tipHash})` };
    }
    if (header.bits !== this.nextBitsFor(header.height)) {
      return { ok: false, error: `wrong difficulty: expected ${this.nextBitsFor(header.height).toString(16)}` };
    }
    if (header.time <= this.medianTimePast()) {
      return { ok: false, error: 'block time must exceed median time past of the last 11 blocks' };
    }

    const draft = this.state.clone();

    // Non-coinbase first: the coinbase's allowance depends on the fees they pay.
    let totalFees = 0n;
    let totalGas = 0;
    const blockLogs: VmLog[] = [];
    for (const tx of block.transactions.slice(1)) {
      const res = this.applyTransaction(tx, draft, { height: header.height, time: header.time });
      if (!res.ok) return { ok: false, error: `tx ${txid(tx)}: ${res.error}` };
      totalFees += res.fee;
      totalGas += res.gasUsed;
      blockLogs.push(...res.logs);
      if (totalGas > BLOCK_GAS_LIMIT) {
        return { ok: false, error: `block gas ${totalGas} exceeds limit ${BLOCK_GAS_LIMIT}` };
      }
    }

    const cbResult = this.applyTransaction(block.transactions[0], draft, {
      height: header.height,
      time: header.time,
      availableFees: totalFees,
    });
    if (!cbResult.ok) return { ok: false, error: `coinbase: ${cbResult.error}` };

    const computedStateRoot = draft.stateRoot();
    if (computedStateRoot !== header.stateRoot) {
      return {
        ok: false,
        error: `state root mismatch: header ${header.stateRoot} vs computed ${computedStateRoot}`,
      };
    }

    this.state = draft;
    this.blocks.push(block);
    this.#work += blockWork(header.bits);
    if (blockLogs.length > 0) this.logsByHeight.set(header.height, blockLogs);

    return {
      ok: true,
      hash: blockHash(header),
      height: header.height,
      totalFees,
      gasUsed: totalGas,
    };
  }

  /* ------------------------------------------------------ block assembly */

  /**
   * Assemble, mine and append a block containing `txs`.
   *
   * Returns the mined block plus the work it took. Transactions that fail to
   * apply are reported rather than silently dropped — a miner that silently
   * drops transactions is indistinguishable from one that is censoring.
   */
  mineBlock(
    txs: readonly Transaction[],
    minerAddress: string,
    opts: { time?: number; memo?: string } = {},
  ): { block: Block; result: AddBlockResult; rejected: Array<{ txid: Hex; error: string }>; attempts: number } {
    const height = this.height + 1;
    const time = opts.time ?? Math.max(Math.floor(Date.now() / 1000), this.medianTimePast() + 1);

    // Dry-run against a draft so we mine only over transactions that will apply.
    const draft = this.state.clone();
    const accepted: Transaction[] = [];
    const rejected: Array<{ txid: Hex; error: string }> = [];
    let fees = 0n;

    for (const tx of txs) {
      const res = this.applyTransaction(tx, draft, { height, time });
      if (res.ok) {
        accepted.push(tx);
        fees += res.fee;
      } else {
        rejected.push({ txid: txid(tx), error: res.error ?? 'unknown' });
      }
    }

    const cb = coinbaseTx(
      minerAddress,
      blockSubsidy(height) + fees,
      height,
      opts.memo ?? `deckx/${height}`,
    );
    this.applyTransaction(cb, draft, { height, time, availableFees: fees });

    const template: BlockHeader = {
      version: 1,
      prevHash: this.tipHash,
      merkleRoot: computeMerkleRoot([cb, ...accepted]),
      stateRoot: draft.stateRoot(),
      time,
      bits: this.nextBitsFor(height),
      height,
      nonce: 0,
      extraNonce: 0,
    };

    const mined = mine(template);
    const block: Block = { header: mined.header, transactions: [cb, ...accepted] };
    const result = this.addBlock(block, time + 1);
    return { block, result, rejected, attempts: mined.attempts };
  }

  /* ------------------------------------------------------------- helpers */

  /** Difficulty for the block at `height`, per the 2016-block retarget schedule. */
  nextBitsFor(height: number): number {
    const currentBits = this.tip.header.bits;
    if (height === 0 || height % RETARGET_INTERVAL !== 0) return currentBits;
    const first = this.blocks[height - RETARGET_INTERVAL];
    const last = this.tip;
    return nextBits(currentBits, last.header.time - first.header.time);
  }

  /**
   * Median of the last 11 block timestamps. Blocks must be strictly newer than
   * this, which is what stops a miner rolling timestamps backwards to make
   * difficulty collapse.
   */
  medianTimePast(): number {
    const window = this.blocks.slice(-11).map((b) => b.header.time).sort((a, b) => a - b);
    return window[Math.floor(window.length / 2)];
  }

  /**
   * Supply audit: the UTXO set must total exactly the sum of subsidies paid.
   *
   * This is the single most valuable invariant in the whole codebase. If it
   * ever drifts, coins were created or destroyed somewhere they should not
   * have been, and every other guarantee is void. It runs at the end of every
   * scenario and in eleven tests.
   */
  auditSupply(): {
    utxoTotal: bigint;
    expectedSubsidy: bigint;
    balanced: boolean;
    percentOfCap: string;
    underCap: boolean;
  } {
    const expected = cumulativeIssuance(this.height);
    const utxoTotal = this.state.totalSupply();
    return {
      utxoTotal,
      expectedSubsidy: expected,
      balanced: utxoTotal === expected,
      percentOfCap: ((Number(utxoTotal) / Number(MAX_SUPPLY)) * 100).toFixed(6),
      underCap: utxoTotal <= MAX_SUPPLY,
    };
  }
}

function failure(error: string, fee = 0n): ApplyResult {
  return { ok: false, error, fee, gasUsed: 0, logs: [] };
}
