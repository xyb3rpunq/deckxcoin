/**
 * Contract authoring toolkit.
 *
 * Writing covenants directly in DVM opcodes is possible but miserable — the
 * stack order of `SSTORE` alone (value then key) has caused more bugs during
 * this project than every cryptographic primitive combined. So the contracts
 * in this directory are assembled from named fragments instead.
 *
 * This is metaprogramming, not a language: each helper returns an array of
 * assembler tokens, and JavaScript composes them. Loops over owners are
 * unrolled at build time, so the deployed bytecode contains no loop and costs
 * no gas for one.
 *
 * ── The covenant contract, restated ───────────────────────────────────────
 * Every contract here answers exactly one question: *may this transaction
 * spend the output I am guarding?* It returns two words:
 *
 *     [0]  approved — non-zero to authorise
 *     [1]  beneficiary — address word some output must pay (0 = unconstrained)
 *
 * Returning a beneficiary is what stops an approval being a bearer token.
 * Never return `[1, 0]` from a contract guarding real value unless you
 * genuinely mean "anyone may take this".
 */

import { OP, addressWord } from '../vm.ts';

/** An assembler token: opcode, immediate, or label. */
export type Tok = number | bigint | string;

export const flat = (...parts: Array<Tok | Tok[]>): Tok[] => parts.flat() as Tok[];

/* ────────────────────────────────────────────────────────── storage ── */

/** `storage[slot]` onto the stack. */
export const load = (slot: number | bigint): Tok[] => [BigInt(slot), OP.SLOAD];

/** `storage[slot] = value`. Emits value before key — the order SSTORE expects. */
export const store = (slot: number | bigint, value: bigint): Tok[] => [
  value,
  BigInt(slot),
  OP.SSTORE,
];

/** `storage[slot] += 1`. */
export const increment = (slot: number | bigint): Tok[] => [
  ...load(slot),
  1n,
  OP.ADD,
  BigInt(slot),
  OP.SSTORE,
];

/* ─────────────────────────────────────────────────────── predicates ── */

/** `blockHeight >= storage[slot]` → 1 or 0. */
export const heightAtLeastSlot = (slot: number | bigint): Tok[] => [
  OP.NUMBER,
  ...load(slot),
  OP.GT, // storage[slot] > NUMBER
  OP.ISZERO, // ⇒ NUMBER >= storage[slot]
];

/** `blockHeight > storage[slot]` → 1 or 0. */
export const heightPastSlot = (slot: number | bigint): Tok[] => [
  ...load(slot),
  OP.NUMBER,
  OP.GT,
];

/** `caller == storage[slot]` → 1 or 0. */
export const callerIsSlot = (slot: number | bigint): Tok[] => [
  OP.CALLER,
  ...load(slot),
  OP.EQ,
];

/** `calldata[i]` onto the stack. Absent words read as zero. */
export const calldata = (index: number): Tok[] => [BigInt(index), OP.CALLDATA];

/** `sha256(calldata[i]) == storage[slot]` → 1 or 0. The hashlock predicate. */
export const preimageMatchesSlot = (index: number, slot: number | bigint): Tok[] => [
  ...calldata(index),
  OP.SHA256,
  ...load(slot),
  OP.EQ,
];

/** Logical OR of two already-pushed predicates. */
export const OR: Tok[] = [OP.OR];
/** Logical AND of two already-pushed predicates. */
export const AND: Tok[] = [OP.AND];

/* ──────────────────────────────────────────────────────── control ──── */

/** Jump to `label` when the top of the stack is non-zero. Consumes it. */
export const jumpIf = (label: string): Tok[] => [`@${label}`, OP.JUMPI];

/** Unconditional jump. */
export const jump = (label: string): Tok[] => [`@${label}`, OP.JUMP];

/** Define a jump target. */
export const label = (name: string): Tok[] => [`${name}:`];

/* ──────────────────────────────────────────────────────── outcomes ── */

export const REKT_TOPIC = 0x52454b54n; // "REKT"
export const DENY_TOPIC = 0x44454e59n; // "DENY"

/** Emit a decision event, then return `[1, storage[beneficiarySlot]]`. */
export const approveTo = (beneficiarySlot: number | bigint, tag = REKT_TOPIC): Tok[] => [
  ...load(beneficiarySlot),
  1n,
  tag,
  OP.LOG, // log the beneficiary that was authorised
  1n,
  ...load(beneficiarySlot),
  2n,
  OP.RETURN,
];

/** Return `[0, 0]` — refuse the spend. */
export const deny = (tag = DENY_TOPIC): Tok[] => [
  0n,
  1n,
  tag,
  OP.LOG,
  0n,
  0n,
  2n,
  OP.RETURN,
];

/* ───────────────────────────────────────────────────── constructor ── */

/*
 * Contracts here open with the same four tokens:
 *
 *     load(0), OP.ISZERO, jumpIf('init'), jump('check')
 *
 * Slot 0 being zero is the "never run before" signal, so every contract stores
 * a block height or a hash there — values that are never legitimately zero.
 * Writing that inline rather than behind a helper keeps the control flow
 * visible in each contract, which matters more than the four saved tokens.
 */

/** Convert an address to the 256-bit word contracts compare against. */
export const word = (address: string): bigint => addressWord(address);

/* ─────────────────────────────────────────────────── documentation ── */

export interface StorageLayout {
  readonly slot: number;
  readonly name: string;
  readonly meaning: string;
}

export interface ContractSpec {
  readonly name: string;
  readonly summary: string;
  /** What the caller must put in calldata, if anything. */
  readonly calldata: readonly string[];
  readonly storage: readonly StorageLayout[];
  /** Plain-language statement of exactly when this contract approves. */
  readonly approvesWhen: readonly string[];
  /** Known limitations. Every contract has some; hiding them is how people lose money. */
  readonly caveats: readonly string[];
}
