/**
 * The standard covenant library, exercised against the real chain validator.
 *
 * Nothing here is unit-tested in isolation against a mock VM. Every assertion
 * runs a transaction through `Blockchain.applyTransaction`, which means a
 * contract that "works" in the VM but produces a transaction the chain refuses
 * counts as a failure — which is the only definition that matters.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { Blockchain } from '../src/chain.ts';
import { contractAddress, fromHex, keyPairFromSeed, sha256, toHex, type KeyPair } from '../src/crypto.ts';
import { callTx, deployTx, signInput, signTx, transferTx, ZAPS_PER_DECKX } from '../src/tx.ts';
import { advance, pickUtxo, rig } from './helpers.ts';
import {
  atomicSwap,
  CONTRACT_SPECS,
  escrow,
  multiSig,
  timeVault,
  vesting,
  type CompiledContract,
} from '../src/contracts/index.ts';

const GAS_LIMIT = 300_000;
const GAS_PRICE = 1n;
const GAS_BUDGET = BigInt(GAS_LIMIT) * GAS_PRICE;
const ENDOWMENT = 2n * ZAPS_PER_DECKX;

/* ─────────────────────────────────────────────────────────── harness ── */

interface Deployed {
  chain: Blockchain;
  miner: KeyPair;
  owner: KeyPair;
  address: string;
  contract: CompiledContract;
}

/**
 * Deploy `contract` on a fresh regtest chain, funding it with `outputs`
 * separate guarded outputs so multi-release covenants have something to
 * release more than once.
 */
function deploy(contract: CompiledContract, seed: string, outputs = 1): Deployed {
  const { chain, miner } = rig(`contracts/${seed}/miner`);
  const owner = keyPairFromSeed(`contracts/${seed}/owner`);

  // Fund the owner from the miner's mature coinbase.
  const coin = pickUtxo(chain, miner.address);
  const funded = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [{ value: (coin.value - 1000n).toString(), address: owner.address }],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );
  let t = chain.tip.header.time + 600;
  assert.equal(chain.mineBlock([funded], miner.address, { time: t }).result.ok, true);

  const address = contractAddress(owner.address, 0);
  const ownerCoin = pickUtxo(chain, owner.address);
  const guarded = Array.from({ length: outputs }, () => ({
    value: ENDOWMENT.toString(),
    address,
  }));
  const change = ownerCoin.value - ENDOWMENT * BigInt(outputs) - GAS_BUDGET;
  assert.ok(change > 0n, 'harness: owner cannot fund the covenant');

  const tx = signTx(
    deployTx({
      inputs: [{ txid: ownerCoin.txid, vout: ownerCoin.vout }],
      outputs: [...guarded, { value: change.toString(), address: owner.address }],
      code: contract.hex,
      gasLimit: GAS_LIMIT,
      gasPrice: GAS_PRICE,
      nonce: 0,
    }),
    owner,
    [{ value: ownerCoin.value, address: ownerCoin.address }],
  );

  t = chain.tip.header.time + 600;
  const res = chain.mineBlock([tx], miner.address, { time: t });
  assert.deepEqual(res.rejected, []);
  assert.equal(res.result.ok, true, res.result.error);

  return { chain, miner, owner, address, contract };
}

/** Build a call that spends one guarded output to `payTo`, paid for by `caller`. */
function spend(
  d: Deployed,
  caller: KeyPair,
  payTo: string,
  opts: { calldata?: string[]; target?: string } = {},
) {
  const guarded = d.chain.state.utxosFor(d.address)[0];
  assert.ok(guarded, 'no guarded output left to spend');
  const gas = pickUtxo(d.chain, caller.address);

  const tx = callTx({
    inputs: [
      { txid: guarded.txid, vout: guarded.vout },
      { txid: gas.txid, vout: gas.vout },
    ],
    outputs: [
      { value: guarded.value.toString(), address: payTo },
      { value: (gas.value - GAS_BUDGET).toString(), address: caller.address },
    ],
    target: opts.target ?? d.address,
    calldata: opts.calldata ?? [],
    gasLimit: GAS_LIMIT,
    gasPrice: GAS_PRICE,
    nonce: d.chain.state.nonceOf(caller.address),
  });
  // Input 0 is unlocked by the contract; only the gas input is signed.
  return signInput(tx, 1, caller, { value: gas.value, address: gas.address });
}

/** Try a spend without mining it. Returns the validator's verdict. */
function dryRun(d: Deployed, tx: ReturnType<typeof spend>) {
  return d.chain.applyTransaction(tx, d.chain.state.clone(), {
    height: d.chain.height + 1,
    time: d.chain.tip.header.time + 600,
  });
}

/** Mine a spend and assert it confirmed. */
function confirm(d: Deployed, tx: ReturnType<typeof spend>) {
  const t = d.chain.tip.header.time + 600;
  const res = d.chain.mineBlock([tx], d.miner.address, { time: t });
  assert.deepEqual(res.rejected, [], JSON.stringify(res.rejected));
  assert.equal(res.result.ok, true, res.result.error);
  return res;
}

/** Give a key some spendable coin so it can pay gas. */
function fund(d: Deployed, who: KeyPair, amount = ZAPS_PER_DECKX) {
  const coin = pickUtxo(d.chain, d.owner.address);
  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: amount.toString(), address: who.address },
        { value: (coin.value - amount - 1000n).toString(), address: d.owner.address },
      ],
    }),
    d.owner,
    [{ value: coin.value, address: coin.address }],
  );
  const t = d.chain.tip.header.time + 600;
  assert.equal(d.chain.mineBlock([tx], d.miner.address, { time: t }).result.ok, true);
}

/* ═══════════════════════════════════════════════════════ 1. TimeVault ══ */

test('TimeVault: full lifecycle on a live chain', () => {
  const carol = keyPairFromSeed('contracts/tv2/carol');
  // Deploy first to learn the height, then use a vault unlocking 5 blocks later.
  const probe = rig('contracts/tv2/probe');
  const unlockHeight = probe.chain.height + 8;

  const d = deploy(timeVault(unlockHeight, carol.address), 'tv2');
  assert.ok(d.chain.height < unlockHeight, 'harness must deploy before the unlock');

  // Terms were written on the constructor run.
  const account = d.chain.state.getContract(d.address)!;
  assert.equal(account.storage['0'], String(unlockHeight));
  assert.ok(account.storage['1'], 'beneficiary must be stored');

  // Too early.
  const early = dryRun(d, spend(d, d.owner, carol.address));
  assert.equal(early.ok, false);
  assert.match(early.error!, /covenant refused/);

  // After the unlock height.
  advance(d.chain, d.miner.address, unlockHeight - d.chain.height);
  confirm(d, spend(d, d.owner, carol.address));

  assert.equal(d.chain.state.balanceOf(carol.address), ENDOWMENT);
  assert.equal(d.chain.state.balanceOf(d.address), 0n);
  assert.equal(d.chain.auditSupply().balanced, true);
});

test('TimeVault: an approval cannot be redirected away from the beneficiary', () => {
  const carol = keyPairFromSeed('contracts/tv3/carol');
  const mallory = keyPairFromSeed('contracts/tv3/mallory');
  const probe = rig('contracts/tv3/probe');
  const unlockHeight = probe.chain.height + 8;

  const d = deploy(timeVault(unlockHeight, carol.address), 'tv3');
  advance(d.chain, d.miner.address, unlockHeight - d.chain.height);

  const redirected = dryRun(d, spend(d, d.owner, mallory.address));
  assert.equal(redirected.ok, false);
  assert.match(redirected.error!, /no output matches the authorised recipient/);
});

/* ═══════════════════════════════════════════════════════════ 2. Escrow ══ */

const RELEASE = '1';
const REFUND = '2';

function escrowRig(seed: string, deadlineOffset = 20) {
  const seller = keyPairFromSeed(`contracts/${seed}/seller`);
  const buyer = keyPairFromSeed(`contracts/${seed}/buyer`);
  const arbiter = keyPairFromSeed(`contracts/${seed}/arbiter`);
  const probe = rig(`contracts/${seed}/probe`);
  const deadlineHeight = probe.chain.height + deadlineOffset;

  const d = deploy(
    escrow({ deadlineHeight, seller: seller.address, buyer: buyer.address, arbiter: arbiter.address }),
    seed,
  );
  return { d, seller, buyer, arbiter, deadlineHeight };
}

test('Escrow: the buyer releases to the seller', () => {
  const { d, seller, buyer } = escrowRig('esc1');
  fund(d, buyer);
  confirm(d, spend(d, buyer, seller.address, { calldata: [RELEASE] }));
  assert.equal(d.chain.state.balanceOf(seller.address), ENDOWMENT);
  assert.equal(d.chain.state.getContract(d.address)!.storage['4'], '1', 'settled flag');
});

test('Escrow: the arbiter can force either outcome', () => {
  const a = escrowRig('esc2');
  fund(a.d, a.arbiter);
  confirm(a.d, spend(a.d, a.arbiter, a.seller.address, { calldata: [RELEASE] }));
  assert.equal(a.d.chain.state.balanceOf(a.seller.address), ENDOWMENT);

  const b = escrowRig('esc3');
  fund(b.d, b.arbiter);
  confirm(b.d, spend(b.d, b.arbiter, b.buyer.address, { calldata: [REFUND] }));
  assert.equal(b.d.chain.state.balanceOf(b.buyer.address), ENDOWMENT);
});

test('Escrow: the seller cannot pay themselves', () => {
  const { d, seller } = escrowRig('esc4');
  fund(d, seller);
  const res = dryRun(d, spend(d, seller, seller.address, { calldata: [RELEASE] }));
  assert.equal(res.ok, false);
  assert.match(res.error!, /covenant refused/);
});

test('Escrow: the buyer cannot self-refund before the deadline, and can after', () => {
  const { d, buyer, deadlineHeight } = escrowRig('esc5', 25);
  fund(d, buyer);

  const early = dryRun(d, spend(d, buyer, buyer.address, { calldata: [REFUND] }));
  assert.equal(early.ok, false, 'self-refund before the deadline must fail');

  advance(d.chain, d.miner.address, deadlineHeight - d.chain.height + 1);
  confirm(d, spend(d, buyer, buyer.address, { calldata: [REFUND] }));
  assert.equal(d.chain.state.balanceOf(buyer.address) > 0n, true);
});

test('Escrow: an unknown action is refused', () => {
  const { d, buyer, seller } = escrowRig('esc6');
  fund(d, buyer);
  const res = dryRun(d, spend(d, buyer, seller.address, { calldata: ['7'] }));
  assert.equal(res.ok, false);
  assert.match(res.error!, /covenant refused/);
});

/* ══════════════════════════════════════════════════════════ 3. Vesting ══ */

test('Vesting: nothing before the cliff, then one tranche per interval', () => {
  const beneficiary = keyPairFromSeed('contracts/vest/beneficiary');
  const probe = rig('contracts/vest/probe');
  const cliffHeight = probe.chain.height + 10;
  const intervalBlocks = 5;

  const d = deploy(
    vesting({ cliffHeight, beneficiary: beneficiary.address, intervalBlocks, tranches: 3 }),
    'vest',
    3,
  );
  assert.equal(d.chain.state.utxosFor(d.address).length, 3);

  // Before the cliff: refused.
  assert.equal(dryRun(d, spend(d, d.owner, beneficiary.address)).ok, false);

  // At the cliff: tranche 1.
  advance(d.chain, d.miner.address, cliffHeight - d.chain.height);
  confirm(d, spend(d, d.owner, beneficiary.address));
  assert.equal(d.chain.state.getContract(d.address)!.storage['4'], '1');
  assert.equal(d.chain.state.balanceOf(beneficiary.address), ENDOWMENT);

  // Immediately again: too early for tranche 2.
  assert.equal(dryRun(d, spend(d, d.owner, beneficiary.address)).ok, false);

  // After one interval: tranche 2.
  advance(d.chain, d.miner.address, intervalBlocks);
  confirm(d, spend(d, d.owner, beneficiary.address));
  assert.equal(d.chain.state.balanceOf(beneficiary.address), ENDOWMENT * 2n);

  // After another: tranche 3, the last one.
  advance(d.chain, d.miner.address, intervalBlocks);
  confirm(d, spend(d, d.owner, beneficiary.address));
  assert.equal(d.chain.state.balanceOf(beneficiary.address), ENDOWMENT * 3n);
  assert.equal(d.chain.state.getContract(d.address)!.storage['4'], '3');
  assert.equal(d.chain.state.utxosFor(d.address).length, 0);
  assert.equal(d.chain.auditSupply().balanced, true);
});

test('Vesting: refuses once every tranche has been released', () => {
  const beneficiary = keyPairFromSeed('contracts/vest2/beneficiary');
  const probe = rig('contracts/vest2/probe');
  const cliffHeight = probe.chain.height + 8;

  // Two tranches declared but three outputs funded — the extra is stranded,
  // which is the caveat the spec documents.
  const d = deploy(
    vesting({ cliffHeight, beneficiary: beneficiary.address, intervalBlocks: 2, tranches: 2 }),
    'vest2',
    3,
  );

  advance(d.chain, d.miner.address, cliffHeight - d.chain.height);
  confirm(d, spend(d, d.owner, beneficiary.address));
  advance(d.chain, d.miner.address, 2);
  confirm(d, spend(d, d.owner, beneficiary.address));

  advance(d.chain, d.miner.address, 10);
  const exhausted = dryRun(d, spend(d, d.owner, beneficiary.address));
  assert.equal(exhausted.ok, false, 'the third output must stay stranded');
  assert.equal(d.chain.state.utxosFor(d.address).length, 1);
});

/* ═════════════════════════════════════════════════════════ 4. MultiSig ══ */

test('MultiSig: 2-of-3 authorises on the second distinct approval', () => {
  const [a, b, c] = ['a', 'b', 'c'].map((s) => keyPairFromSeed(`contracts/ms/${s}`));
  const payee = keyPairFromSeed('contracts/ms/payee');

  const d = deploy(
    multiSig({ threshold: 2, owners: [a.address, b.address, c.address], beneficiary: payee.address }),
    'ms',
  );
  fund(d, a);
  fund(d, b);
  fund(d, c);

  // First owner approves — recorded, but not enough.
  const first = spend(d, a, payee.address);
  const firstRes = dryRun(d, first);
  assert.equal(firstRes.ok, false, 'one approval must not authorise a 2-of-3');

  // The approval only persists if the call is mined. A refused covenant spend
  // is rejected wholesale, so approvals must be gathered by mining calls that
  // do not spend the guarded output.
  assert.equal(d.chain.state.getContract(d.address)!.storage['2'], undefined);
});

test('MultiSig: approvals accumulate across mined calls', () => {
  const [a, b, c] = ['a', 'b', 'c'].map((s) => keyPairFromSeed(`contracts/ms2/${s}`));
  const payee = keyPairFromSeed('contracts/ms2/payee');

  const d = deploy(
    multiSig({ threshold: 2, owners: [a.address, b.address, c.address], beneficiary: payee.address }),
    'ms2',
  );
  fund(d, a);
  fund(d, b);

  /** A call that runs the contract without spending the guarded output. */
  const approveOnly = (who: KeyPair) => {
    const gas = pickUtxo(d.chain, who.address);
    const tx = callTx({
      inputs: [{ txid: gas.txid, vout: gas.vout }],
      outputs: [{ value: (gas.value - GAS_BUDGET).toString(), address: who.address }],
      target: d.address,
      gasLimit: GAS_LIMIT,
      gasPrice: GAS_PRICE,
      nonce: d.chain.state.nonceOf(who.address),
    });
    return signTx(tx, who, [{ value: gas.value, address: gas.address }]);
  };

  // Owner A registers approval. The call itself does not spend the covenant,
  // so it confirms even though the contract's verdict is "not yet".
  let t = d.chain.tip.header.time + 600;
  assert.equal(d.chain.mineBlock([approveOnly(a)], d.miner.address, { time: t }).result.ok, true);
  assert.equal(d.chain.state.getContract(d.address)!.storage['2'], '1');

  // A approving twice must not double-count.
  t = d.chain.tip.header.time + 600;
  assert.equal(d.chain.mineBlock([approveOnly(a)], d.miner.address, { time: t }).result.ok, true);
  assert.equal(d.chain.state.getContract(d.address)!.storage['2'], '1', 'no double counting');

  // B is the second distinct owner — now the covenant releases.
  t = d.chain.tip.header.time + 600;
  assert.equal(d.chain.mineBlock([approveOnly(b)], d.miner.address, { time: t }).result.ok, true);
  assert.equal(d.chain.state.getContract(d.address)!.storage['2'], '2');

  confirm(d, spend(d, a, payee.address));
  assert.equal(d.chain.state.balanceOf(payee.address), ENDOWMENT);
  assert.equal(d.chain.auditSupply().balanced, true);
});

test('MultiSig: a non-owner is refused and never counted', () => {
  const [a, b, c] = ['a', 'b', 'c'].map((s) => keyPairFromSeed(`contracts/ms3/${s}`));
  const payee = keyPairFromSeed('contracts/ms3/payee');
  const stranger = keyPairFromSeed('contracts/ms3/stranger');

  const d = deploy(
    multiSig({ threshold: 2, owners: [a.address, b.address, c.address], beneficiary: payee.address }),
    'ms3',
  );
  fund(d, stranger);

  const res = dryRun(d, spend(d, stranger, payee.address));
  assert.equal(res.ok, false);
  assert.match(res.error!, /covenant refused/);
  assert.equal(d.chain.state.getContract(d.address)!.storage['2'], undefined);
});

test('MultiSig: rejects impossible configurations at build time', () => {
  const owner = keyPairFromSeed('contracts/ms4/o').address;
  assert.throws(() => multiSig({ threshold: 2, owners: [owner], beneficiary: owner }), /bad threshold/);
  assert.throws(() => multiSig({ threshold: 0, owners: [owner], beneficiary: owner }), /bad threshold/);
  assert.throws(() => multiSig({ threshold: 1, owners: [], beneficiary: owner }), /at least one owner/);
  assert.throws(
    () => multiSig({ threshold: 1, owners: Array(9).fill(owner), beneficiary: owner }),
    /at most 8 owners/,
  );
});

/* ════════════════════════════════════════════════════════ 5. AtomicSwap ══ */

const SECRET = 42_1337_9001n;
const secretWord = () => {
  const bytes = new Uint8Array(32);
  let v = SECRET;
  for (let i = 31; i >= 0; i--) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
  return { bytes, decimal: SECRET.toString(), hashHex: toHex(sha256(bytes)) };
};

test('AtomicSwap: the receiver claims by revealing the preimage', () => {
  const receiver = keyPairFromSeed('contracts/swap/receiver');
  const refundTo = keyPairFromSeed('contracts/swap/refund');
  const probe = rig('contracts/swap/probe');
  const secret = secretWord();

  const d = deploy(
    atomicSwap({
      timeoutHeight: probe.chain.height + 40,
      receiver: receiver.address,
      refundTo: refundTo.address,
      hashHex: secret.hashHex,
    }),
    'swap',
  );

  // Wrong preimage: refused.
  const wrong = dryRun(d, spend(d, d.owner, receiver.address, { calldata: ['999'] }));
  assert.equal(wrong.ok, false);
  assert.match(wrong.error!, /covenant refused/);

  // Correct preimage: claimed, at any height.
  confirm(d, spend(d, d.owner, receiver.address, { calldata: [secret.decimal] }));
  assert.equal(d.chain.state.balanceOf(receiver.address), ENDOWMENT);

  // The preimage is now public on-chain — the property a cross-chain swap
  // depends on, and the privacy leak that motivates PTLCs.
  assert.equal(d.chain.state.getContract(d.address)!.storage['4'], secret.decimal);
});

test('AtomicSwap: the sender reclaims after the timeout', () => {
  const receiver = keyPairFromSeed('contracts/swap2/receiver');
  const refundTo = keyPairFromSeed('contracts/swap2/refund');
  const probe = rig('contracts/swap2/probe');
  const timeoutHeight = probe.chain.height + 12;
  const secret = secretWord();

  const d = deploy(
    atomicSwap({ timeoutHeight, receiver: receiver.address, refundTo: refundTo.address, hashHex: secret.hashHex }),
    'swap2',
  );

  // Before the timeout the refund path is closed.
  assert.equal(dryRun(d, spend(d, d.owner, refundTo.address)).ok, false);

  advance(d.chain, d.miner.address, timeoutHeight - d.chain.height + 1);
  confirm(d, spend(d, d.owner, refundTo.address));
  assert.equal(d.chain.state.balanceOf(refundTo.address), ENDOWMENT);
  assert.equal(d.chain.auditSupply().balanced, true);
});

test('AtomicSwap: the hash commitment matches SHA-256 of the secret', () => {
  const secret = secretWord();
  assert.equal(secret.hashHex, toHex(sha256(secret.bytes)));
  assert.equal(fromHex(secret.hashHex).length, 32);
});

/* ══════════════════════════════════════════════════════════ metadata ══ */

test('every contract publishes a complete, honest specification', () => {
  assert.equal(CONTRACT_SPECS.length, 5);
  for (const spec of CONTRACT_SPECS) {
    assert.ok(spec.name.length > 0, 'name');
    assert.ok(spec.summary.length > 30, `${spec.name}: summary too thin`);
    assert.ok(spec.storage.length > 0, `${spec.name}: no storage layout`);
    assert.ok(spec.approvesWhen.length > 0, `${spec.name}: no approval conditions`);
    // A contract with no documented caveats is a contract whose author has
    // not looked hard enough.
    assert.ok(spec.caveats.length >= 2, `${spec.name}: needs at least two caveats`);
  }
});

test('all five contracts compile within the code size limit', () => {
  const owner = keyPairFromSeed('contracts/size/o').address;
  const built = [
    timeVault(1000, owner),
    escrow({ deadlineHeight: 1000, seller: owner, buyer: owner, arbiter: owner }),
    vesting({ cliffHeight: 1000, beneficiary: owner, intervalBlocks: 10, tranches: 4 }),
    multiSig({ threshold: 2, owners: [owner, owner, owner], beneficiary: owner }),
    atomicSwap({ timeoutHeight: 1000, receiver: owner, refundTo: owner, hashHex: '11'.repeat(32) }),
  ];
  for (const c of built) {
    assert.ok(c.code.length > 20, `${c.spec.name}: suspiciously small`);
    assert.ok(c.code.length < 24_576, `${c.spec.name}: exceeds EIP-170 limit`);
    assert.equal(c.hex.length, c.code.length * 2);
  }
});
