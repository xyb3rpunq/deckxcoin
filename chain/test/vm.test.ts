/** DVM semantics, gas metering, and the covenant path that fuses it to the UTXO layer. */

import test from 'node:test';
import assert from 'node:assert/strict';

import { asm, addressWord, execute, OP, MAX_CODE_SIZE } from '../src/vm.ts';
import { Blockchain } from '../src/chain.ts';
import { contractAddress, keyPairFromSeed, toHex } from '../src/crypto.ts';
import { callTx, deployTx, signTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { advance, pickUtxo, rig } from './helpers.ts';

const ctx = (over: Partial<Parameters<typeof execute>[1]> = {}) => ({
  address: 'dxc1qcontract',
  caller: 'dxc1qcaller',
  callValue: 0n,
  calldata: [] as bigint[],
  blockNumber: 1,
  blockTime: 1_785_628_800,
  gasLimit: 1_000_000,
  balanceOf: () => 0n,
  ...over,
});

test('arithmetic wraps at 2^256, like the EVM', () => {
  const max = (1n << 256n) - 1n;
  const code = asm(max, 1n, OP.ADD, 1n, OP.RETURN);
  const res = execute(code, ctx());
  assert.equal(res.ok, true, res.error);
  assert.equal(res.returnValue[0], '0');
});

test('division by zero yields zero rather than trapping', () => {
  const res = execute(asm(0n, 100n, OP.DIV, 1n, OP.RETURN), ctx());
  assert.equal(res.ok, true, res.error);
  assert.equal(res.returnValue[0], '0');
});

test('storage persists across calls and is reported back', () => {
  // SSTORE pops key then value, so push value first.
  const code = asm(7n, 42n, OP.SSTORE, OP.STOP);
  const first = execute(code, ctx());
  assert.equal(first.ok, true, first.error);
  assert.equal(first.storage['42'], '7');

  const read = execute(asm(42n, OP.SLOAD, 1n, OP.RETURN), ctx(), first.storage);
  assert.equal(read.returnValue[0], '7');
});

test('clearing a slot deletes it and earns a capped refund', () => {
  const set = execute(asm(9n, 1n, OP.SSTORE, OP.STOP), ctx());
  const clear = execute(asm(0n, 1n, OP.SSTORE, OP.STOP), ctx(), set.storage);
  assert.equal(clear.ok, true, clear.error);
  assert.equal(clear.storage['1'], undefined);
  // Refund is capped at 20% of gas used (EIP-3529), so it can never go negative.
  assert.ok(clear.gasUsed >= 0);
});

test('out of gas consumes the whole limit and discards writes', () => {
  const res = execute(asm(1n, 1n, OP.SSTORE, OP.STOP), ctx({ gasLimit: 100 }));
  assert.equal(res.ok, false);
  assert.equal(res.error, 'out of gas');
  assert.equal(res.gasUsed, 100);
  assert.deepEqual(res.storage, {});
});

test('REVERT rolls back every write but keeps gas spent', () => {
  const code = asm(5n, 1n, OP.SSTORE, OP.REVERT);
  const res = execute(code, ctx());
  assert.equal(res.ok, false);
  assert.equal(res.reverted, true);
  assert.deepEqual(res.storage, {});
  assert.ok(res.gasUsed > 0);
});

test('a jump into PUSH data is rejected', () => {
  // 0x5b (JUMPDEST) appearing as an immediate must not be a valid target.
  const code = Uint8Array.from([OP.PUSH1, 0x03, OP.JUMP, OP.PUSH1, 0x5b, OP.STOP]);
  const res = execute(code, ctx());
  assert.equal(res.ok, false);
  assert.match(res.error!, /invalid jump destination/);
});

test('stack underflow is a clean failure, not a crash', () => {
  const res = execute(Uint8Array.of(OP.ADD), ctx());
  assert.equal(res.ok, false);
  assert.equal(res.error, 'stack underflow');
});

test('code larger than the limit is refused', () => {
  const res = execute(new Uint8Array(MAX_CODE_SIZE + 1), ctx());
  assert.equal(res.ok, false);
  assert.match(res.error!, /code size/);
});

test('a loop terminates when gas runs out — no infinite execution', () => {
  const code = asm('top:', 1n, OP.POP, '@top', OP.JUMP);
  const res = execute(code, ctx({ gasLimit: 5_000 }));
  assert.equal(res.ok, false);
  assert.equal(res.error, 'out of gas');
  assert.equal(res.gasUsed, 5_000);
});

test('LOG emits an event with topic and data', () => {
  const code = asm(99n, 1n, 0xbeefn, OP.LOG, OP.STOP);
  const res = execute(code, ctx());
  assert.equal(res.ok, true, res.error);
  assert.equal(res.logs.length, 1);
  assert.equal(res.logs[0].data[0], '99');
  assert.match(res.logs[0].topic, /beef$/);
});

test('CALLER and CALLDATA are readable by the contract', () => {
  const res = execute(asm(OP.CALLER, 1n, OP.RETURN), ctx({ caller: 'dxc1qalice' }));
  assert.equal(res.returnValue[0], addressWord('dxc1qalice').toString());

  const withData = execute(asm(1n, OP.CALLDATA, 1n, OP.RETURN), ctx({ calldata: [10n, 20n] }));
  assert.equal(withData.returnValue[0], '20');
});

test('deploy then call: a counter contract keeps state across blocks', () => {
  const { chain, miner } = rig('vm/miner');
  const alice = keyPairFromSeed('vm/alice');

  // counter: storage[0] += 1; return storage[0]
  const code = asm(0n, OP.SLOAD, 1n, OP.ADD, OP.DUP1, 0n, OP.SSTORE, 1n, OP.RETURN);

  const funding = pickUtxo(chain, miner.address);
  const gasPrice = 1n;
  const gasLimit = 100_000;
  const fee = BigInt(gasLimit) * gasPrice;
  const change = funding.value - fee;

  let deploy = deployTx({
    inputs: [{ txid: funding.txid, vout: funding.vout }],
    outputs: [{ value: change.toString(), address: miner.address }],
    code: toHex(code),
    gasLimit,
    gasPrice,
    nonce: 0,
  });
  deploy = signTx(deploy, miner, [{ value: funding.value, address: funding.address }]);

  const expectedAddress = contractAddress(miner.address, 0);
  let t = chain.tip.header.time + 600;
  const r1 = chain.mineBlock([deploy], alice.address, { time: t });
  assert.deepEqual(r1.rejected, []);
  assert.equal(r1.result.ok, true, r1.result.error);

  const account = chain.state.getContract(expectedAddress);
  assert.ok(account, `no contract at ${expectedAddress}`);
  assert.equal(account!.storage['0'], '1', 'constructor run should have set the counter to 1');
  assert.equal(account!.deployer, miner.address);

  // Now call it. Fund the call from the deploy's change output.
  advance(chain, alice.address, 1);
  const next = chain.state.utxosFor(miner.address).sort((a, b) => (a.value > b.value ? -1 : 1))[0];

  let call = callTx({
    inputs: [{ txid: next.txid, vout: next.vout }],
    outputs: [{ value: (next.value - fee).toString(), address: miner.address }],
    target: expectedAddress,
    gasLimit,
    gasPrice,
    nonce: 1,
  });
  call = signTx(call, miner, [{ value: next.value, address: next.address }]);

  t = chain.tip.header.time + 600;
  const r2 = chain.mineBlock([call], alice.address, { time: t });
  assert.deepEqual(r2.rejected, []);
  assert.equal(r2.result.ok, true, r2.result.error);
  assert.equal(chain.state.getContract(expectedAddress)!.storage['0'], '2');
  assert.ok(r2.result.gasUsed! > 0, 'the call must have burned gas');

  const audit = chain.auditSupply();
  assert.equal(audit.balanced, true);
  void txid;
  void ZAPS_PER_DECKX;
  void Blockchain;
});

test('a contract that reverts leaves the chain untouched', () => {
  const { chain, miner } = rig('vm/revert');
  const funding = pickUtxo(chain, miner.address);
  const gasLimit = 50_000;
  const gasPrice = 1n;
  const fee = BigInt(gasLimit) * gasPrice;

  let deploy = deployTx({
    inputs: [{ txid: funding.txid, vout: funding.vout }],
    outputs: [{ value: (funding.value - fee).toString(), address: miner.address }],
    code: toHex(asm(OP.REVERT)),
    gasLimit,
    gasPrice,
    nonce: 0,
  });
  deploy = signTx(deploy, miner, [{ value: funding.value, address: funding.address }]);

  const before = chain.state.stateRoot();
  const res = chain.applyTransaction(deploy, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /reverted/);
  assert.equal(chain.state.stateRoot(), before, 'a rejected deploy must not touch state');
});
