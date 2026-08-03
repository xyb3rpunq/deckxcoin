/**
 * DeckxCoin standard covenant library.
 *
 * Five contracts covering the patterns that account-model chains normally
 * implement as custodial token contracts — vaults, escrow, vesting, multisig,
 * atomic swaps — but implemented as *spending conditions on outputs* rather
 * than as pots of pooled value.
 *
 * The structural difference matters. On Ethereum, a vesting contract holds
 * everyone's tokens; a bug in it drains all of them. Here, a vesting covenant
 * guards one output belonging to one beneficiary. The blast radius of a bug is
 * the output, not the protocol.
 *
 * Every contract:
 *   • initialises its terms on first execution and never again;
 *   • returns `[approved, beneficiary]`, so approvals cannot be redirected;
 *   • emits a log so an explorer can show the decision;
 *   • is covered by tests in `test/contracts.test.ts` that run against the
 *     real chain validator, not a mock.
 *
 * ── Regulatory note ───────────────────────────────────────────────────────
 * These are mechanical spending conditions. None of them mints a fungible
 * claim on a common enterprise, promises a return, pools contributions from
 * multiple parties, or names an issuer with ongoing obligations. That is a
 * deliberate design boundary, documented in `docs/COMPLIANCE.md`, not an
 * accident of scope.
 */

import { toHex } from '../crypto.ts';
import { asm, OP } from '../vm.ts';
import {
  approveTo,
  callerIsSlot,
  calldata,
  deny,
  flat,
  heightAtLeastSlot,
  heightPastSlot,
  increment,
  jump,
  jumpIf,
  label,
  load,
  preimageMatchesSlot,
  store,
  word,
  type ContractSpec,
  type Tok,
} from './lib.ts';

export * from './lib.ts';

export interface CompiledContract {
  readonly spec: ContractSpec;
  readonly code: Uint8Array;
  readonly hex: string;
}

const compile = (spec: ContractSpec, tokens: Tok[]): CompiledContract => {
  const code = asm(...tokens);
  return { spec, code, hex: toHex(code) };
};

/* ═══════════════════════════════════════════════════════ 1. TimeVault ══ */

export const TIME_VAULT_SPEC: ContractSpec = {
  name: 'TimeVault',
  summary:
    'Releases a guarded output to one fixed beneficiary, and only once the chain reaches a fixed height.',
  calldata: [],
  storage: [
    { slot: 0, name: 'unlockHeight', meaning: 'block height at or after which the spend is allowed' },
    { slot: 1, name: 'beneficiary', meaning: 'address word that must receive an output' },
    { slot: 2, name: 'attempts', meaning: 'every release attempt, approved or not' },
  ],
  approvesWhen: ['the current block height is greater than or equal to `unlockHeight`'],
  caveats: [
    'There is no cancel path. Once funded, the output is unreachable until the height passes — including by the depositor.',
    'Block height is not wall-clock time. A stalled chain delays the unlock.',
  ],
};

/**
 * The reference covenant. Bitcoin needs an unactivated soft fork (CTV) to
 * express this; Ethereum expresses it easily but the contract must custody the
 * funds. Here the output stays a UTXO and the contract only answers yes or no.
 */
export function timeVault(unlockHeight: number, beneficiary: string): CompiledContract {
  return compile(
    TIME_VAULT_SPEC,
    flat(
      // Seed terms on first run only.
      load(0),
      OP.ISZERO,
      jumpIf('init'),
      jump('check'),

      label('init'),
      store(0, BigInt(unlockHeight)),
      store(1, word(beneficiary)),

      label('check'),
      increment(2),
      heightAtLeastSlot(0),
      jumpIf('ok'),
      deny(),

      label('ok'),
      approveTo(1),
    ),
  );
}

/* ═══════════════════════════════════════════════════════════ 2. Escrow ══ */

export const ESCROW_SPEC: ContractSpec = {
  name: 'Escrow',
  summary:
    'Two-party escrow with an arbiter and a refund deadline. Release pays the seller; refund pays the buyer.',
  calldata: ['[0] action — 1 = release to seller, 2 = refund to buyer'],
  storage: [
    { slot: 0, name: 'deadline', meaning: 'height after which the buyer may self-refund' },
    { slot: 1, name: 'seller', meaning: 'address word paid on release' },
    { slot: 2, name: 'buyer', meaning: 'address word paid on refund' },
    { slot: 3, name: 'arbiter', meaning: 'may force either outcome at any time' },
    { slot: 4, name: 'settled', meaning: '1 once an outcome has been approved' },
  ],
  approvesWhen: [
    'action = 1 (release) and the caller is the buyer or the arbiter',
    'action = 2 (refund) and the caller is the seller or the arbiter',
    'action = 2 (refund) and the caller is the buyer and the deadline has passed',
  ],
  caveats: [
    'The arbiter is fully trusted for both outcomes. This is a trust-minimised escrow, not a trustless one.',
    'The deadline is the buyer\'s only unilateral exit. Choose it deliberately.',
    '`settled` records that an outcome happened; it does not prevent a second guarded output from being released the same way.',
  ],
};

export function escrow(opts: {
  deadlineHeight: number;
  seller: string;
  buyer: string;
  arbiter: string;
}): CompiledContract {
  return compile(
    ESCROW_SPEC,
    flat(
      load(0),
      OP.ISZERO,
      jumpIf('init'),
      jump('dispatch'),

      label('init'),
      store(0, BigInt(opts.deadlineHeight)),
      store(1, word(opts.seller)),
      store(2, word(opts.buyer)),
      store(3, word(opts.arbiter)),

      label('dispatch'),
      // action == 1 → release
      calldata(0),
      1n,
      OP.EQ,
      jumpIf('release'),
      // action == 2 → refund
      calldata(0),
      2n,
      OP.EQ,
      jumpIf('refund'),
      deny(),

      /* ---- release: buyer confirms delivery, or the arbiter rules ---- */
      label('release'),
      callerIsSlot(2), // buyer
      callerIsSlot(3), // arbiter
      OP.OR,
      jumpIf('doRelease'),
      deny(),

      label('doRelease'),
      store(4, 1n),
      approveTo(1), // → seller

      /* ---- refund: seller concedes, arbiter rules, or deadline passed - */
      label('refund'),
      callerIsSlot(1), // seller
      callerIsSlot(3), // arbiter
      OP.OR,
      jumpIf('doRefund'),
      // buyer may self-refund only once the deadline has passed
      callerIsSlot(2),
      heightPastSlot(0),
      OP.AND,
      jumpIf('doRefund'),
      deny(),

      label('doRefund'),
      store(4, 1n),
      approveTo(2), // → buyer
    ),
  );
}

/* ══════════════════════════════════════════════════════════ 3. Vesting ══ */

export const VESTING_SPEC: ContractSpec = {
  name: 'Vesting',
  summary:
    'Releases guarded outputs to one beneficiary in tranches: nothing before the cliff, then one tranche per interval.',
  calldata: [],
  storage: [
    { slot: 0, name: 'cliffHeight', meaning: 'height of the first possible release' },
    { slot: 1, name: 'beneficiary', meaning: 'address word that must receive an output' },
    { slot: 2, name: 'interval', meaning: 'blocks between tranches' },
    { slot: 3, name: 'tranches', meaning: 'total number of tranches' },
    { slot: 4, name: 'released', meaning: 'tranches released so far' },
  ],
  approvesWhen: [
    'released < tranches, and',
    'height >= cliff + released × interval',
  ],
  caveats: [
    'Each approved spend counts as one tranche regardless of the amount. Fund the covenant with one output per tranche, of equal size.',
    'There is no clawback. An employee who leaves still vests on schedule unless the arrangement is enforced off-chain.',
  ],
};

export function vesting(opts: {
  cliffHeight: number;
  beneficiary: string;
  intervalBlocks: number;
  tranches: number;
}): CompiledContract {
  return compile(
    VESTING_SPEC,
    flat(
      load(0),
      OP.ISZERO,
      jumpIf('init'),
      jump('check'),

      label('init'),
      store(0, BigInt(opts.cliffHeight)),
      store(1, word(opts.beneficiary)),
      store(2, BigInt(opts.intervalBlocks)),
      store(3, BigInt(opts.tranches)),

      label('check'),
      // released < tranches ?  LT pops (a=top, b=next) and pushes a < b, so
      // the operands are emitted tranches-then-released to read as written.
      load(3),
      load(4),
      OP.LT,
      OP.ISZERO, // ⇒ no tranches left
      jumpIf('exhausted'),

      // height >= cliff + released × interval ?
      OP.NUMBER,
      load(0),
      load(4),
      load(2),
      OP.MUL,
      OP.ADD, // cliff + released*interval
      OP.GT, // due > NUMBER
      OP.ISZERO, // ⇒ NUMBER >= due
      jumpIf('ok'),
      deny(),

      label('exhausted'),
      deny(),

      label('ok'),
      increment(4),
      approveTo(1),
    ),
  );
}

/* ═════════════════════════════════════════════════════════ 4. MultiSig ══ */

export const MULTISIG_SPEC: ContractSpec = {
  name: 'MultiSig',
  summary:
    'M-of-N approval. Each owner calls once to register approval; the spend is authorised on the Mth distinct approval.',
  calldata: [],
  storage: [
    { slot: 0, name: 'threshold', meaning: 'M — approvals required' },
    { slot: 1, name: 'beneficiary', meaning: 'address word that must receive an output' },
    { slot: 2, name: 'approvals', meaning: 'distinct owners who have approved so far' },
    { slot: 10, name: 'owners[i]', meaning: 'owner address words, slots 10..10+N-1' },
    { slot: -1, name: '<callerWord>', meaning: 'set to 1 once that owner has approved (keyed by address word)' },
  ],
  approvesWhen: ['the caller is a listed owner, and their approval brings the distinct count to M or more'],
  caveats: [
    'Approvals accumulate across transactions. Each approving call costs a fee, so M-of-N costs M transactions.',
    'There is no revocation and no expiry. An approval given today still counts a year later.',
    'The beneficiary is fixed at deployment. Owners approve a payee, not an arbitrary spend.',
  ],
};

const OWNER_BASE = 10;

export function multiSig(opts: {
  threshold: number;
  owners: readonly string[];
  beneficiary: string;
}): CompiledContract {
  const { threshold, owners, beneficiary } = opts;
  if (owners.length < 1) throw new Error('multiSig: need at least one owner');
  if (owners.length > 8) throw new Error('multiSig: at most 8 owners (bytecode is unrolled)');
  if (threshold < 1 || threshold > owners.length) throw new Error('multiSig: bad threshold');

  // Unrolled owner check — one comparison per owner, OR-ed together. A loop
  // would cost gas at runtime to save bytes that cost gas once, at deploy.
  const ownerCheck: Tok[] = [];
  owners.forEach((_, i) => {
    ownerCheck.push(...callerIsSlot(OWNER_BASE + i));
    if (i > 0) ownerCheck.push(OP.OR);
  });

  return compile(
    MULTISIG_SPEC,
    flat(
      load(0),
      OP.ISZERO,
      jumpIf('init'),
      jump('check'),

      label('init'),
      store(0, BigInt(threshold)),
      store(1, word(beneficiary)),
      ...owners.map((owner, i) => store(OWNER_BASE + i, word(owner))),

      label('check'),
      // Is the caller a listed owner?
      ownerCheck,
      jumpIf('isOwner'),
      deny(),

      label('isOwner'),
      // Already approved? storage[callerWord] — arbitrary 256-bit keys are
      // legal, so the caller's own address word is its approval slot.
      OP.CALLER,
      OP.SLOAD,
      jumpIf('tally'),
      // First approval from this owner: record it and count it.
      1n,
      OP.CALLER,
      OP.SSTORE,
      increment(2),

      label('tally'),
      // approvals >= threshold ?
      load(2),
      load(0),
      OP.GT, // threshold > approvals
      OP.ISZERO, // ⇒ approvals >= threshold
      jumpIf('ok'),
      deny(),

      label('ok'),
      approveTo(1),
    ),
  );
}

/* ════════════════════════════════════════════════════════ 5. AtomicSwap ══ */

export const ATOMIC_SWAP_SPEC: ContractSpec = {
  name: 'AtomicSwap',
  summary:
    'Hash-time-locked covenant. The receiver claims by revealing a preimage; the sender reclaims after a timeout.',
  calldata: ['[0] preimage — a 256-bit word whose SHA-256 equals `hash`'],
  storage: [
    { slot: 0, name: 'timeout', meaning: 'height after which the refund path opens' },
    { slot: 1, name: 'receiver', meaning: 'paid when the preimage is revealed' },
    { slot: 2, name: 'refund', meaning: 'paid after the timeout' },
    { slot: 3, name: 'hash', meaning: 'SHA-256 of the secret, as a 256-bit word' },
    { slot: 4, name: 'revealed', meaning: 'the preimage, once someone has published it' },
  ],
  approvesWhen: [
    'calldata[0] hashes to `hash` — pays the receiver, at any height',
    'the height is past `timeout` — pays the refund address',
  ],
  caveats: [
    'Revealing the preimage on this chain reveals it to everyone. That is the point for a cross-chain swap, and a privacy leak for anything else — the same reason Lightning is migrating from HTLCs to PTLCs.',
    'The timeout must give the counterparty enough time on the other chain. Too short and the swap becomes a free option against you.',
    'Once past the timeout, the refund path stays open even if the preimage is later revealed — first to broadcast wins.',
  ],
};

export function atomicSwap(opts: {
  timeoutHeight: number;
  receiver: string;
  refundTo: string;
  /** SHA-256 of the secret, as a 32-byte hex string. */
  hashHex: string;
}): CompiledContract {
  const hashWord = BigInt('0x' + opts.hashHex.replace(/^0x/, ''));

  return compile(
    ATOMIC_SWAP_SPEC,
    flat(
      load(0),
      OP.ISZERO,
      jumpIf('init'),
      jump('check'),

      label('init'),
      store(0, BigInt(opts.timeoutHeight)),
      store(1, word(opts.receiver)),
      store(2, word(opts.refundTo)),
      store(3, hashWord),

      label('check'),
      // Hashlock branch — valid at any height.
      preimageMatchesSlot(0, 3),
      jumpIf('claim'),
      // Timeout branch.
      heightPastSlot(0),
      jumpIf('refund'),
      deny(),

      label('claim'),
      // Publish the preimage so a watcher on the other chain can lift it.
      calldata(0),
      4n,
      OP.SSTORE,
      approveTo(1),

      label('refund'),
      approveTo(2),
    ),
  );
}

/* ═══════════════════════════════════════════════════════════ registry ══ */

export const CONTRACT_SPECS: readonly ContractSpec[] = [
  TIME_VAULT_SPEC,
  ESCROW_SPEC,
  VESTING_SPEC,
  MULTISIG_SPEC,
  ATOMIC_SWAP_SPEC,
];
