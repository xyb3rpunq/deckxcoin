/**
 * Transactions.
 *
 * DeckxCoin keeps Bitcoin's UTXO model as the *value* layer and bolts the
 * DVM on as a *state* layer. One transaction envelope carries both:
 *
 *   transfer — pure UTXO movement. No VM, no state root change beyond the
 *              UTXO set. This is whitepaper §2, verbatim.
 *   deploy   — spends UTXOs, and additionally installs contract code at a
 *              deterministically derived address.
 *   call     — spends UTXOs, and additionally runs a contract, mutating its
 *              storage. Gas is bought with the transaction fee.
 *   coinbase — no inputs, creates the block subsidy.
 *
 * Why UTXO and not accounts? Two reasons that matter for this project:
 * parallel validation (inputs name their own history, so signature checking
 * fans out), and — the reason that actually drove the choice — payment
 * channels. Volt needs a funding output that two parties jointly own and can
 * spend into competing commitment transactions. That is natural in UTXO and
 * awkward in an account model.
 *
 * Signature hashing follows BIP-143's shape: every input signs a digest that
 * commits to *all* inputs and *all* outputs. The malleability and
 * quadratic-hashing problems of Bitcoin's original SIGHASH are not
 * reproduced.
 */

import {
  addressFromPubkey,
  beBytes,
  contractAddress,
  fromHex,
  isContractAddress,
  isValidAddress,
  PUBKEY_BYTES,
  sha256 as sha256Bytes,
  sign,
  taggedHash,
  toHex,
  utf8,
  verify,
  type Hex,
  type KeyPair,
} from './crypto.ts';

/** Smallest unit. 1 DECKX = 100,000,000 zaps — same 8-decimal granularity as Bitcoin. */
export const ZAPS_PER_DECKX = 100_000_000n;
export const MAX_MONEY = 21_000_000n * ZAPS_PER_DECKX;

export const TX_KIND = {
  COINBASE: 'coinbase',
  TRANSFER: 'transfer',
  DEPLOY: 'deploy',
  CALL: 'call',
} as const;

export type TxKind = (typeof TX_KIND)[keyof typeof TX_KIND];

export interface TxInput {
  /** Transaction being spent. */
  readonly txid: Hex;
  /** Index of the output being spent. */
  readonly vout: number;
  /** 32-byte x-only BIP-340 pubkey whose HASH160 must match the output's address. */
  readonly pubkey: Hex;
  /** 64-byte BIP-340 Schnorr signature over the sighash. */
  readonly signature: Hex;
  /** BIP-68 style relative locktime in blocks. Volt uses this for revocation windows. */
  readonly sequence: number;
  /**
   * Second signature for a 2-of-2 output. Witness data: excluded from the
   * txid, included in the wtxid. Volt's funding outputs live here.
   */
  readonly cosign?: { readonly pubkey: Hex; readonly signature: Hex };
  /**
   * HTLC preimage. Witness data. Presenting it takes the hashlock branch of
   * an `htlc` output; omitting it takes the timeout branch.
   */
  readonly preimage?: Hex;
}

export interface TxOutput {
  /** Value in zaps, decimal string (JSON has no bigint). */
  readonly value: string;
  /** Recipient address, or a multisig script hash for channel funding. */
  readonly address: string;
  /**
   * Optional spending predicate beyond "one signature from `address`".
   * Volt funding outputs set `{ type: 'multisig2', keys: [a, b] }`.
   */
  readonly script?: OutputScript;
}

export type OutputScript =
  /** Default: one signature from the output's address. */
  | { readonly type: 'p2pkh' }
  /** Volt channel funding: both parties must sign. */
  | { readonly type: 'multisig2'; readonly keys: readonly [Hex, Hex] }
  /** Hash-time-locked contract: preimage before `timeout`, refund key after. */
  | { readonly type: 'htlc'; readonly hash: Hex; readonly timeout: number; readonly refundKey: Hex }
  /**
   * Volt `to_local`: the owner may sweep only after `delay` blocks, but the
   * holder of `revocationKey` may sweep immediately and forever. This is what
   * punishes broadcasting a revoked commitment.
   */
  | { readonly type: 'revocable'; readonly delay: number; readonly revocationKey: Hex };

export interface ContractPayload {
  /** Contract bytecode, hex. Present on `deploy`. */
  readonly code?: Hex;
  /** Target contract. Present on `call`. */
  readonly target?: string;
  /** Flat 256-bit words, decimal strings. */
  readonly calldata: readonly string[];
  readonly gasLimit: number;
  /** Zaps per gas unit. */
  readonly gasPrice: string;
  /** Deployer nonce — makes the contract address predictable and replay-safe. */
  readonly nonce: number;
}

export interface Transaction {
  readonly version: number;
  readonly kind: TxKind;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly lockTime: number;
  readonly contract?: ContractPayload;
  /** Free-form note, ≤ 80 bytes. Bitcoin's OP_RETURN allowance, same limit, same reason. */
  readonly memo?: string;
}

export const MAX_MEMO_BYTES = 80;

/* ---------------------------------------------------------------- encoding */

/**
 * Canonical serialisation. Field order is fixed and every variable-length
 * field is length-prefixed, so two distinct transactions can never share an
 * encoding. Everything the txid must commit to appears here — the signature
 * is the sole exclusion, which is what makes txids non-malleable.
 */
export function serializeTx(tx: Transaction, opts: { withSignatures: boolean }): Uint8Array {
  const parts: Uint8Array[] = [
    beBytes(BigInt(tx.version), 4),
    lenPrefixed(utf8(tx.kind)),
    beBytes(BigInt(tx.inputs.length), 4),
  ];

  for (const input of tx.inputs) {
    parts.push(fromHex(input.txid));
    parts.push(beBytes(BigInt(input.vout), 4));
    parts.push(beBytes(BigInt(input.sequence), 4));
    /*
     * Pubkey, signature, cosignature and preimage are *witness* data: they
     * authorise the transaction but are not part of its identity. Excluding
     * them from the txid preimage is what makes txids non-malleable — nobody
     * can change a transaction's id by re-encoding its signature. It is also
     * what makes signing well-defined: the digest cannot depend on a field
     * that only exists after the digest has been signed.
     */
    if (opts.withSignatures) {
      parts.push(lenPrefixed(fromHex(input.pubkey)));
      parts.push(lenPrefixed(fromHex(input.signature)));
      parts.push(lenPrefixed(utf8(input.cosign ? `${input.cosign.pubkey}:${input.cosign.signature}` : '')));
      parts.push(lenPrefixed(utf8(input.preimage ?? '')));
    }
  }

  parts.push(beBytes(BigInt(tx.outputs.length), 4));
  for (const output of tx.outputs) {
    parts.push(beBytes(BigInt(output.value), 8));
    parts.push(lenPrefixed(utf8(output.address)));
    parts.push(lenPrefixed(utf8(output.script ? JSON.stringify(output.script) : '')));
  }

  parts.push(beBytes(BigInt(tx.lockTime), 4));
  parts.push(lenPrefixed(utf8(tx.contract ? canonicalContract(tx.contract) : '')));
  parts.push(lenPrefixed(utf8(tx.memo ?? '')));

  return concatAll(parts);
}

function canonicalContract(c: ContractPayload): string {
  // Explicit key order — JSON.stringify's insertion order is not a spec guarantee we want to rely on.
  return JSON.stringify([c.code ?? '', c.target ?? '', c.calldata, c.gasLimit, c.gasPrice, c.nonce]);
}

function lenPrefixed(data: Uint8Array): Uint8Array {
  return concatAll([beBytes(BigInt(data.length), 4), data]);
}

function concatAll(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/**
 * Transaction id — double-SHA256 over the signature-stripped encoding.
 * Bitcoin only achieved this with segwit; DeckxCoin has it from genesis, so
 * a txid is a stable reference the moment a transaction is built.
 */
export function txid(tx: Transaction): Hex {
  return toHex(taggedHash('DeckxCoin/txid', serializeTx(tx, { withSignatures: false })));
}

/** Witness id — commits to signatures too. Used for the block's witness commitment. */
export function wtxid(tx: Transaction): Hex {
  return toHex(taggedHash('DeckxCoin/wtxid', serializeTx(tx, { withSignatures: true })));
}

/* --------------------------------------------------------------- signing */

/**
 * Digest signed by input `index`. Commits to the whole transaction plus the
 * value and address of the output being spent — the BIP-143 fix that stops a
 * wallet being tricked into signing away a larger UTXO than it was shown.
 */
export function sighash(
  tx: Transaction,
  index: number,
  prevValue: bigint,
  prevAddress: string,
): Uint8Array {
  return taggedHash(
    'DeckxCoin/sighash',
    serializeTx(tx, { withSignatures: false }),
    beBytes(BigInt(index), 4),
    beBytes(prevValue, 8),
    utf8(prevAddress),
  );
}

export interface PrevOut {
  readonly value: bigint;
  readonly address: string;
  readonly script?: OutputScript;
}

/** Sign every input of `tx` with `key`, returning a new transaction. */
export function signTx(tx: Transaction, key: KeyPair, prevOuts: readonly PrevOut[]): Transaction {
  if (prevOuts.length !== tx.inputs.length) {
    throw new Error('signTx: prevOuts length must match inputs length');
  }
  const inputs = tx.inputs.map((input, i) => ({
    ...input,
    pubkey: toHex(key.publicKey),
    signature: sign(sighash(tx, i, prevOuts[i].value, prevOuts[i].address), key.privateKey),
  }));
  return { ...tx, inputs };
}

/** Sign a single input. Used when a transaction has inputs owned by different keys. */
export function signInput(
  tx: Transaction,
  index: number,
  key: KeyPair,
  prev: PrevOut,
): Transaction {
  const digest = sighash(tx, index, prev.value, prev.address);
  const inputs = tx.inputs.map((input, i) =>
    i === index
      ? { ...input, pubkey: toHex(key.publicKey), signature: sign(digest, key.privateKey) }
      : input,
  );
  return { ...tx, inputs };
}

/** Attach the second signature of a 2-of-2. The counterparty's half of a commitment. */
export function cosignInput(
  tx: Transaction,
  index: number,
  key: KeyPair,
  prev: PrevOut,
): Transaction {
  const digest = sighash(tx, index, prev.value, prev.address);
  const inputs = tx.inputs.map((input, i) =>
    i === index
      ? {
          ...input,
          cosign: { pubkey: toHex(key.publicKey), signature: sign(digest, key.privateKey) },
        }
      : input,
  );
  return { ...tx, inputs };
}

/** Attach an HTLC preimage to an input, taking the hashlock branch. */
export function withPreimage(tx: Transaction, index: number, preimage: Hex): Transaction {
  const inputs = tx.inputs.map((input, i) => (i === index ? { ...input, preimage } : input));
  return { ...tx, inputs };
}

/* ------------------------------------------------------------- validation */

export interface TxCheck {
  readonly ok: boolean;
  readonly error?: string;
  /** inputs − outputs, in zaps. Zero for coinbase. */
  readonly fee: bigint;
}

const ok = (fee: bigint): TxCheck => ({ ok: true, fee });
const bad = (error: string): TxCheck => ({ ok: false, error, fee: 0n });

/**
 * Stateless + prevout-aware validation. Does *not* check the UTXO set for
 * double spends — that is the chain's job, because it needs the whole block
 * context to catch two transactions spending the same output.
 */
export function checkTx(tx: Transaction, prevOuts: readonly PrevOut[]): TxCheck {
  if (tx.version !== 1) return bad(`unsupported tx version ${tx.version}`);
  if (tx.outputs.length === 0) return bad('transaction has no outputs');
  if (tx.memo !== undefined && utf8(tx.memo).length > MAX_MEMO_BYTES) {
    return bad(`memo exceeds ${MAX_MEMO_BYTES} bytes`);
  }

  let outputSum = 0n;
  for (const out of tx.outputs) {
    let value: bigint;
    try {
      value = BigInt(out.value);
    } catch {
      return bad(`output value is not an integer: ${out.value}`);
    }
    if (value < 0n) return bad('negative output value');
    if (value > MAX_MONEY) return bad('output exceeds max money');
    if (!isValidAddress(out.address)) return bad(`invalid output address ${out.address}`);
    outputSum += value;
    if (outputSum > MAX_MONEY) return bad('output sum exceeds max money');
  }

  if (tx.kind === TX_KIND.COINBASE) {
    if (tx.inputs.length !== 0) return bad('coinbase must have no inputs');
    return ok(0n);
  }

  if (tx.inputs.length === 0) return bad('non-coinbase transaction has no inputs');
  if (prevOuts.length !== tx.inputs.length) return bad('prevOuts/inputs length mismatch');

  // Reject duplicate outpoints inside a single transaction outright.
  const seen = new Set<string>();
  for (const input of tx.inputs) {
    const key = `${input.txid}:${input.vout}`;
    if (seen.has(key)) return bad(`duplicate input ${key}`);
    seen.add(key);
  }

  let inputSum = 0n;
  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    const prev = prevOuts[i];
    inputSum += prev.value;

    /*
     * Covenant inputs. An output paid to a version-1 (contract) address is not
     * locked by a key at all — it is locked by *code*. Authorisation is the
     * contract returning a non-zero word when this very transaction is passed
     * to it, which the chain checks after the VM runs. This is the fusion
     * point of the whole design: Bitcoin's outputs, Ethereum's authoriser.
     */
    if (isContractAddress(prev.address)) {
      if (tx.kind !== TX_KIND.CALL) {
        return bad(`input ${i}: contract-locked output requires a 'call' transaction`);
      }
      if (tx.contract?.target !== prev.address) {
        return bad(`input ${i}: call must target the locking contract ${prev.address}`);
      }
      continue;
    }

    const pubkey = fromHex(input.pubkey);
    if (pubkey.length !== PUBKEY_BYTES) {
      return bad(`input ${i}: pubkey must be ${PUBKEY_BYTES} bytes (BIP-340 x-only)`);
    }

    const script = prev.script ?? { type: 'p2pkh' as const };
    const digest = sighash(tx, i, prev.value, prev.address);

    if (script.type === 'p2pkh') {
      if (addressFromPubkey(pubkey) !== prev.address) {
        return bad(`input ${i}: pubkey does not match output address`);
      }
    } else if (script.type === 'multisig2') {
      /*
       * True 2-of-2: both parties must sign the same digest. This is the
       * output a Volt channel is funded into — neither side can move the
       * money alone, which is the entire security model of a payment channel.
       */
      if (!input.cosign) return bad(`input ${i}: 2-of-2 output requires a cosignature`);
      const [keyA, keyB] = script.keys;
      const provided = [input.pubkey, input.cosign.pubkey].sort();
      const expected = [keyA, keyB].sort();
      if (provided[0] !== expected[0] || provided[1] !== expected[1]) {
        return bad(`input ${i}: cosigners are not the two channel parties`);
      }
      if (!verify(input.cosign.signature, digest, fromHex(input.cosign.pubkey))) {
        return bad(`input ${i}: bad cosignature`);
      }
    } else if (script.type === 'htlc') {
      /*
       * Hash-time-locked contract, the primitive that makes trustless
       * multi-hop routing possible (whitepaper of Poon–Dryja, §3). Two
       * branches, mutually exclusive:
       *   • preimage branch — payee sweeps by revealing x where H(x) = hash;
       *   • timeout branch  — payer refunds after `timeout`, enforced by the
       *                       chain's absolute locktime rule.
       */
      const claimed = input.preimage
        ? toHex(sha256Bytes(fromHex(input.preimage))) === script.hash
        : false;
      if (claimed) {
        if (addressFromPubkey(pubkey) !== prev.address) {
          return bad(`input ${i}: htlc preimage branch requires the payee key`);
        }
      } else {
        if (input.preimage) return bad(`input ${i}: htlc preimage does not hash to the commitment`);
        if (input.pubkey !== script.refundKey) {
          return bad(`input ${i}: htlc timeout branch requires the refund key`);
        }
        if (tx.lockTime < script.timeout) {
          return bad(`input ${i}: htlc refund requires lockTime >= ${script.timeout}`);
        }
      }
    } else if (script.type === 'revocable') {
      /*
       * The asymmetry that makes payment channels safe. The owner's own funds
       * are encumbered by a relative timelock; the counterparty's revocation
       * key is not. Broadcast an old state and you hand your entire channel
       * balance to the person you tried to cheat.
       */
      if (input.pubkey === script.revocationKey) {
        // Penalty branch — immediate, no delay, no further conditions.
      } else {
        if (addressFromPubkey(pubkey) !== prev.address) {
          return bad(`input ${i}: revocable output requires the owner or the revocation key`);
        }
        if ((input.sequence & 0x0000ffff) < script.delay) {
          return bad(`input ${i}: revocable output requires sequence >= ${script.delay}`);
        }
      }
    }

    if (!verify(input.signature, digest, pubkey)) return bad(`input ${i}: bad signature`);
  }

  if (inputSum > MAX_MONEY) return bad('input sum exceeds max money');
  if (outputSum > inputSum) {
    return bad(`outputs (${outputSum}) exceed inputs (${inputSum})`);
  }

  const fee = inputSum - outputSum;

  if (tx.kind === TX_KIND.DEPLOY || tx.kind === TX_KIND.CALL) {
    const c = tx.contract;
    if (!c) return bad(`${tx.kind} transaction has no contract payload`);
    if (c.gasLimit <= 0) return bad('gasLimit must be positive');
    if (c.gasLimit > 10_000_000) return bad('gasLimit exceeds block gas ceiling');
    const gasPrice = BigInt(c.gasPrice);
    if (gasPrice < 0n) return bad('negative gasPrice');
    const maxGasCost = BigInt(c.gasLimit) * gasPrice;
    if (maxGasCost > fee) {
      return bad(`fee ${fee} cannot cover gasLimit*gasPrice ${maxGasCost}`);
    }
    if (tx.kind === TX_KIND.DEPLOY && !c.code) return bad('deploy transaction has no code');
    if (tx.kind === TX_KIND.CALL && !c.target) return bad('call transaction has no target');
  }

  return ok(fee);
}

/* ----------------------------------------------------------- constructors */

export function coinbaseTx(
  to: string,
  value: bigint,
  height: number,
  memo: string,
): Transaction {
  return {
    version: 1,
    kind: TX_KIND.COINBASE,
    inputs: [],
    outputs: [{ value: value.toString(), address: to }],
    // Height in lockTime makes every coinbase txid unique (BIP-34's purpose).
    lockTime: height,
    memo,
  };
}

export interface TransferSpec {
  readonly inputs: ReadonlyArray<{ txid: Hex; vout: number; sequence?: number }>;
  readonly outputs: readonly TxOutput[];
  readonly lockTime?: number;
  readonly memo?: string;
}

export function transferTx(spec: TransferSpec): Transaction {
  return {
    version: 1,
    kind: TX_KIND.TRANSFER,
    inputs: spec.inputs.map((i) => ({
      txid: i.txid,
      vout: i.vout,
      pubkey: '',
      signature: '',
      sequence: i.sequence ?? 0xffffffff,
    })),
    outputs: spec.outputs,
    lockTime: spec.lockTime ?? 0,
    memo: spec.memo,
  };
}

export function deployTx(
  spec: TransferSpec & { code: Hex; calldata?: string[]; gasLimit: number; gasPrice: bigint; nonce: number },
): Transaction {
  return {
    ...transferTx(spec),
    kind: TX_KIND.DEPLOY,
    contract: {
      code: spec.code,
      calldata: spec.calldata ?? [],
      gasLimit: spec.gasLimit,
      gasPrice: spec.gasPrice.toString(),
      nonce: spec.nonce,
    },
  };
}

export function callTx(
  spec: TransferSpec & { target: string; calldata?: string[]; gasLimit: number; gasPrice: bigint; nonce: number },
): Transaction {
  return {
    ...transferTx(spec),
    kind: TX_KIND.CALL,
    contract: {
      target: spec.target,
      calldata: spec.calldata ?? [],
      gasLimit: spec.gasLimit,
      gasPrice: spec.gasPrice.toString(),
      nonce: spec.nonce,
    },
  };
}

export const predictedContractAddress = contractAddress;

/** Human-friendly formatting: 12345678900 zaps → "123.45678900 DECKX". */
export function formatDeckx(zaps: bigint): string {
  const negative = zaps < 0n;
  const abs = negative ? -zaps : zaps;
  const whole = abs / ZAPS_PER_DECKX;
  const frac = (abs % ZAPS_PER_DECKX).toString().padStart(8, '0');
  return `${negative ? '-' : ''}${whole}.${frac} DECKX`;
}
