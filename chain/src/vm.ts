/**
 * DVM — the Deckx Virtual Machine.
 *
 * This is the Ethereum half of the fusion. Where Bitcoin Script is a
 * predicate evaluator (stack in, true/false out, no loops, no state), the DVM
 * is a general stack machine with persistent per-contract storage, metered
 * execution, and reverts that roll back every write.
 *
 * Design decisions and why:
 *
 *  • 256-bit words, like the EVM. Not because 256 bits is a good machine word
 *    — it isn't — but because it makes a hash digest a single stack item, and
 *    every meaningful contract manipulates digests.
 *
 *  • Gas is charged *before* each opcode executes, so an out-of-gas condition
 *    can never leave a half-applied state write. Out-of-gas reverts state but
 *    still consumes the full limit: that is what makes spamming expensive.
 *
 *  • No CALL / DELEGATECALL. Cross-contract reentrancy is the single largest
 *    source of value lost on Ethereum. DeckxCoin contracts are leaves: they
 *    can read chain context and their own storage, and nothing else. This
 *    removes reentrancy as a bug class entirely rather than asking every
 *    developer to remember a mutex.
 *
 *  • Execution is a pure function of (code, calldata, context, storage). No
 *    clock, no randomness, no I/O. Two nodes replaying the same block always
 *    reach the same state root.
 */

import { beBytes, beToBigInt, sha256, toHex, type Hex } from './crypto.ts';

const WORD = 256n;
const MASK = (1n << WORD) - 1n;
const wrap = (v: bigint): bigint => BigInt.asUintN(256, v);

/* ------------------------------------------------------------- opcode table */

export const OP = {
  STOP: 0x00,
  ADD: 0x01,
  MUL: 0x02,
  SUB: 0x03,
  DIV: 0x04,
  MOD: 0x05,
  EXP: 0x0a,
  LT: 0x10,
  GT: 0x11,
  EQ: 0x14,
  ISZERO: 0x15,
  AND: 0x16,
  OR: 0x17,
  XOR: 0x18,
  NOT: 0x19,
  SHL: 0x1b,
  SHR: 0x1c,
  SHA256: 0x20,
  ADDRESS: 0x30,
  BALANCE: 0x31,
  CALLER: 0x33,
  CALLVALUE: 0x34,
  CALLDATA: 0x35,
  CALLDATASIZE: 0x36,
  NUMBER: 0x43,
  TIMESTAMP: 0x42,
  POP: 0x50,
  SLOAD: 0x54,
  SSTORE: 0x55,
  JUMP: 0x56,
  JUMPI: 0x57,
  PC: 0x58,
  GAS: 0x5a,
  JUMPDEST: 0x5b,
  PUSH1: 0x60,
  PUSH32: 0x7f,
  DUP1: 0x80,
  DUP16: 0x8f,
  SWAP1: 0x90,
  SWAP16: 0x9f,
  LOG: 0xa0,
  RETURN: 0xf3,
  REVERT: 0xfd,
  INVALID: 0xfe,
} as const;

/** Base gas cost per opcode. PUSH/DUP/SWAP families share one entry each. */
const GAS: Record<number, number> = {
  [OP.STOP]: 0,
  [OP.ADD]: 3,
  [OP.MUL]: 5,
  [OP.SUB]: 3,
  [OP.DIV]: 5,
  [OP.MOD]: 5,
  [OP.EXP]: 10,
  [OP.LT]: 3,
  [OP.GT]: 3,
  [OP.EQ]: 3,
  [OP.ISZERO]: 3,
  [OP.AND]: 3,
  [OP.OR]: 3,
  [OP.XOR]: 3,
  [OP.NOT]: 3,
  [OP.SHL]: 3,
  [OP.SHR]: 3,
  [OP.SHA256]: 60,
  [OP.ADDRESS]: 2,
  [OP.BALANCE]: 100,
  [OP.CALLER]: 2,
  [OP.CALLVALUE]: 2,
  [OP.CALLDATA]: 3,
  [OP.CALLDATASIZE]: 2,
  [OP.NUMBER]: 2,
  [OP.TIMESTAMP]: 2,
  [OP.POP]: 2,
  [OP.SLOAD]: 100,
  // SSTORE's cost depends on whether the slot was previously zero, so it is
  // charged inside the handler rather than from this table.
  [OP.SSTORE]: 0,
  [OP.JUMP]: 8,
  [OP.JUMPI]: 10,
  [OP.PC]: 2,
  [OP.GAS]: 2,
  [OP.JUMPDEST]: 1,
  [OP.LOG]: 375,
  [OP.RETURN]: 0,
  [OP.REVERT]: 0,
};

const GAS_PUSH = 3;
const GAS_DUP = 3;
const GAS_SWAP = 3;
/** Writing a slot that was previously zero. Storage growth is the expensive resource. */
const GAS_SSTORE_SET = 20_000;
/** Overwriting an already-populated slot. */
const GAS_SSTORE_RESET = 2_900;
/** Refunded (never paid) when a slot is cleared back to zero — encourages cleanup. */
const GAS_SSTORE_CLEAR_REFUND = 4_800;

export const MAX_STACK = 1024;
export const MAX_CODE_SIZE = 24_576; // EIP-170's limit, same reasoning: bound worst-case validation.

/* ------------------------------------------------------------------ context */

export interface VmContext {
  /** Address of the contract being executed. */
  readonly address: string;
  /** Address that initiated this call. */
  readonly caller: string;
  /** DECKX (in zaps) attached to the call. */
  readonly callValue: bigint;
  /** ABI-free calldata: a flat list of 256-bit words. */
  readonly calldata: readonly bigint[];
  readonly blockNumber: number;
  readonly blockTime: number;
  readonly gasLimit: number;
  /** Balance lookup for OP.BALANCE. Injected so the VM stays pure. */
  readonly balanceOf: (address: string) => bigint;
}

export interface VmLog {
  readonly address: string;
  readonly topic: Hex;
  readonly data: readonly string[];
}

export interface VmResult {
  readonly ok: boolean;
  /** Reason string when `ok` is false. */
  readonly error?: string;
  readonly gasUsed: number;
  readonly returnValue: readonly string[];
  readonly logs: readonly VmLog[];
  /** Storage after execution. Empty (i.e. discarded) when the call reverted. */
  readonly storage: Record<string, string>;
  readonly reverted: boolean;
}

/* --------------------------------------------------------------- assembler */

type AsmToken = number | bigint | string;

/**
 * Tiny assembler. `asm(OP.PUSH1, 1n, OP.PUSH1, 2n, OP.ADD)` — a bigint
 * following a PUSH opcode is encoded as its immediate, minimally sized.
 * Labels are plain strings: `'loop:'` defines, `'@loop'` references.
 */
export function asm(...tokens: AsmToken[]): Uint8Array {
  const bytes: number[] = [];
  const labels = new Map<string, number>();
  const patches: Array<{ at: number; label: string }> = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    if (typeof t === 'string') {
      if (t.endsWith(':')) {
        labels.set(t.slice(0, -1), bytes.length);
        bytes.push(OP.JUMPDEST);
        continue;
      }
      if (t.startsWith('@')) {
        // Reserve a PUSH2 with a placeholder destination, patched after layout.
        bytes.push(OP.PUSH1 + 1);
        patches.push({ at: bytes.length, label: t.slice(1) });
        bytes.push(0, 0);
        continue;
      }
      throw new Error(`asm: unknown token ${t}`);
    }

    if (typeof t === 'bigint') {
      const raw = minimalBytes(t);
      bytes.push(OP.PUSH1 + raw.length - 1, ...raw);
      continue;
    }

    bytes.push(t);
  }

  for (const { at, label } of patches) {
    const dest = labels.get(label);
    if (dest === undefined) throw new Error(`asm: undefined label ${label}`);
    bytes[at] = (dest >> 8) & 0xff;
    bytes[at + 1] = dest & 0xff;
  }
  return Uint8Array.from(bytes);
}

function minimalBytes(v: bigint): number[] {
  if (v < 0n) throw new RangeError('asm: negative immediate');
  if (v === 0n) return [0];
  const out: number[] = [];
  let x = v & MASK;
  while (x > 0n) {
    out.unshift(Number(x & 0xffn));
    x >>= 8n;
  }
  if (out.length > 32) throw new RangeError('asm: immediate exceeds 32 bytes');
  return out;
}

/* ------------------------------------------------------------------ execute */

/**
 * Run `code`. Never throws on contract-level faults — a bad contract returns
 * `{ ok: false }` with gas consumed, exactly like a failed EVM call. Only
 * genuine host bugs throw.
 */
export function execute(
  code: Uint8Array,
  ctx: VmContext,
  storageIn: Record<string, string> = {},
): VmResult {
  if (code.length > MAX_CODE_SIZE) {
    return fail('code size exceeds limit', ctx.gasLimit, storageIn);
  }

  const stack: bigint[] = [];
  const storage = new Map<string, bigint>(
    Object.entries(storageIn).map(([k, v]) => [k, BigInt(v)]),
  );
  const logs: VmLog[] = [];
  const jumpdests = scanJumpdests(code);

  let pc = 0;
  let gasUsed = 0;
  let refund = 0;

  const charge = (amount: number): boolean => {
    if (gasUsed + amount > ctx.gasLimit) {
      gasUsed = ctx.gasLimit;
      return false;
    }
    gasUsed += amount;
    return true;
  };

  const pop = (): bigint => {
    const v = stack.pop();
    if (v === undefined) throw new StackUnderflow();
    return v;
  };

  const push = (v: bigint): void => {
    if (stack.length >= MAX_STACK) throw new StackOverflow();
    stack.push(wrap(v));
  };

  try {
    while (pc < code.length) {
      const op = code[pc];

      /* --- PUSH1..PUSH32 ------------------------------------------------ */
      if (op >= OP.PUSH1 && op <= OP.PUSH32) {
        if (!charge(GAS_PUSH)) return outOfGas(gasUsed, storageIn);
        const width = op - OP.PUSH1 + 1;
        if (pc + 1 + width > code.length) {
          return fail('truncated PUSH immediate', gasUsed, storageIn);
        }
        push(beToBigInt(code.slice(pc + 1, pc + 1 + width)));
        pc += 1 + width;
        continue;
      }

      /* --- DUP1..DUP16 -------------------------------------------------- */
      if (op >= OP.DUP1 && op <= OP.DUP16) {
        if (!charge(GAS_DUP)) return outOfGas(gasUsed, storageIn);
        const depth = op - OP.DUP1 + 1;
        if (stack.length < depth) throw new StackUnderflow();
        push(stack[stack.length - depth]);
        pc++;
        continue;
      }

      /* --- SWAP1..SWAP16 ------------------------------------------------ */
      if (op >= OP.SWAP1 && op <= OP.SWAP16) {
        if (!charge(GAS_SWAP)) return outOfGas(gasUsed, storageIn);
        const depth = op - OP.SWAP1 + 1;
        if (stack.length < depth + 1) throw new StackUnderflow();
        const top = stack.length - 1;
        const other = top - depth;
        [stack[top], stack[other]] = [stack[other], stack[top]];
        pc++;
        continue;
      }

      /* --- fixed-cost opcodes ------------------------------------------- */
      const base = GAS[op];
      if (base === undefined) return fail(`invalid opcode 0x${op.toString(16)}`, ctx.gasLimit, storageIn);

      if (op !== OP.SSTORE && !charge(base)) return outOfGas(gasUsed, storageIn);

      switch (op) {
        case OP.STOP:
          return done(gasUsed, refund, [], logs, storage);

        case OP.ADD: push(pop() + pop()); break;
        case OP.MUL: push(pop() * pop()); break;
        case OP.SUB: { const a = pop(), b = pop(); push(a - b); break; }
        case OP.DIV: { const a = pop(), b = pop(); push(b === 0n ? 0n : a / b); break; }
        case OP.MOD: { const a = pop(), b = pop(); push(b === 0n ? 0n : a % b); break; }
        case OP.EXP: {
          const b = pop(), e = pop();
          if (!charge(50 * byteLen(e))) return outOfGas(gasUsed, storageIn);
          push(modPow(b, e));
          break;
        }
        case OP.LT: { const a = pop(), b = pop(); push(a < b ? 1n : 0n); break; }
        case OP.GT: { const a = pop(), b = pop(); push(a > b ? 1n : 0n); break; }
        case OP.EQ: { const a = pop(), b = pop(); push(a === b ? 1n : 0n); break; }
        case OP.ISZERO: push(pop() === 0n ? 1n : 0n); break;
        case OP.AND: push(pop() & pop()); break;
        case OP.OR: push(pop() | pop()); break;
        case OP.XOR: push(pop() ^ pop()); break;
        case OP.NOT: push(~pop() & MASK); break;
        case OP.SHL: { const s = pop(), v = pop(); push(s >= 256n ? 0n : v << s); break; }
        case OP.SHR: { const s = pop(), v = pop(); push(s >= 256n ? 0n : v >> s); break; }

        case OP.SHA256: {
          const v = pop();
          push(beToBigInt(sha256(beBytes(v, 32))));
          break;
        }

        case OP.ADDRESS: push(addressWord(ctx.address)); break;
        case OP.CALLER: push(addressWord(ctx.caller)); break;
        case OP.CALLVALUE: push(ctx.callValue); break;
        case OP.BALANCE: {
          const who = pop();
          // Only the executing contract's own balance is addressable; probing
          // arbitrary accounts is a privacy leak with no legitimate use here.
          push(who === addressWord(ctx.address) ? ctx.balanceOf(ctx.address) : 0n);
          break;
        }
        case OP.CALLDATA: {
          const i = pop();
          push(i < BigInt(ctx.calldata.length) ? ctx.calldata[Number(i)] : 0n);
          break;
        }
        case OP.CALLDATASIZE: push(BigInt(ctx.calldata.length)); break;
        case OP.NUMBER: push(BigInt(ctx.blockNumber)); break;
        case OP.TIMESTAMP: push(BigInt(ctx.blockTime)); break;
        case OP.PC: push(BigInt(pc)); break;
        case OP.GAS: push(BigInt(Math.max(0, ctx.gasLimit - gasUsed))); break;
        case OP.POP: pop(); break;
        case OP.JUMPDEST: break;

        case OP.SLOAD: {
          const key = pop();
          push(storage.get(slot(key)) ?? 0n);
          break;
        }

        case OP.SSTORE: {
          const key = pop();
          const value = pop();
          const k = slot(key);
          const previous = storage.get(k) ?? 0n;
          const cost = previous === 0n && value !== 0n ? GAS_SSTORE_SET : GAS_SSTORE_RESET;
          if (!charge(cost)) return outOfGas(gasUsed, storageIn);
          if (value === 0n) {
            if (previous !== 0n) refund += GAS_SSTORE_CLEAR_REFUND;
            storage.delete(k);
          } else {
            storage.set(k, value);
          }
          break;
        }

        case OP.JUMP: {
          const dest = Number(pop());
          if (!jumpdests.has(dest)) return fail('invalid jump destination', ctx.gasLimit, storageIn);
          pc = dest;
          continue;
        }

        case OP.JUMPI: {
          const dest = Number(pop());
          const cond = pop();
          if (cond !== 0n) {
            if (!jumpdests.has(dest)) return fail('invalid jump destination', ctx.gasLimit, storageIn);
            pc = dest;
            continue;
          }
          break;
        }

        case OP.LOG: {
          const topic = pop();
          const count = Number(pop());
          if (count > 8) return fail('LOG: too many data words', ctx.gasLimit, storageIn);
          if (!charge(count * 8)) return outOfGas(gasUsed, storageIn);
          const data: string[] = [];
          for (let i = 0; i < count; i++) data.unshift(pop().toString());
          logs.push({ address: ctx.address, topic: toHex(beBytes(topic, 32)), data });
          break;
        }

        case OP.RETURN: {
          const count = Number(pop());
          if (count > 16) return fail('RETURN: too many words', ctx.gasLimit, storageIn);
          const out: string[] = [];
          for (let i = 0; i < count; i++) out.unshift(pop().toString());
          return done(gasUsed, refund, out, logs, storage);
        }

        case OP.REVERT: {
          // State is discarded; gas already spent stays spent.
          return {
            ok: false,
            error: 'execution reverted',
            gasUsed,
            returnValue: [],
            logs: [],
            storage: storageIn,
            reverted: true,
          };
        }

        default:
          return fail(`unhandled opcode 0x${op.toString(16)}`, ctx.gasLimit, storageIn);
      }
      pc++;
    }

    return done(gasUsed, refund, [], logs, storage);
  } catch (err) {
    if (err instanceof StackUnderflow) return fail('stack underflow', ctx.gasLimit, storageIn);
    if (err instanceof StackOverflow) return fail('stack overflow', ctx.gasLimit, storageIn);
    throw err;
  }
}

/* ------------------------------------------------------------------ helpers */

class StackUnderflow extends Error {}
class StackOverflow extends Error {}

function scanJumpdests(code: Uint8Array): Set<number> {
  const dests = new Set<number>();
  for (let i = 0; i < code.length; i++) {
    const op = code[i];
    // Skip PUSH immediates so a 0x5b byte inside data is never a valid target.
    if (op >= OP.PUSH1 && op <= OP.PUSH32) i += op - OP.PUSH1 + 1;
    else if (op === OP.JUMPDEST) dests.add(i);
  }
  return dests;
}

const slot = (key: bigint): string => key.toString();

/** Fold an address into a 256-bit word so contracts can compare identities. */
export function addressWord(address: string): bigint {
  return beToBigInt(sha256(new TextEncoder().encode(address))) & MASK;
}

function byteLen(v: bigint): number {
  let n = 0;
  let x = v;
  while (x > 0n) { x >>= 8n; n++; }
  return n;
}

/** Bounded exponentiation — modular by construction since results wrap at 2^256. */
function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = wrap(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = wrap(result * b);
    b = wrap(b * b);
    e >>= 1n;
  }
  return result;
}

function done(
  gasUsed: number,
  refund: number,
  returnValue: string[],
  logs: VmLog[],
  storage: Map<string, bigint>,
): VmResult {
  // Refunds are capped at 20% of gas used, mirroring EIP-3529's anti-gas-token rule.
  const applied = Math.min(refund, Math.floor(gasUsed / 5));
  return {
    ok: true,
    gasUsed: gasUsed - applied,
    returnValue,
    logs,
    storage: Object.fromEntries([...storage].map(([k, v]) => [k, v.toString()])),
    reverted: false,
  };
}

function fail(error: string, gasUsed: number, storage: Record<string, string>): VmResult {
  return { ok: false, error, gasUsed, returnValue: [], logs: [], storage, reverted: false };
}

const outOfGas = (gasUsed: number, storage: Record<string, string>): VmResult =>
  fail('out of gas', gasUsed, storage);
