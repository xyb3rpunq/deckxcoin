/**
 * Covenants — the fusion point.
 *
 * An output paid to a contract address has no key behind it. The only way to
 * spend it is a `call` transaction that the contract approves. These tests
 * cover the three things that must hold for that to be safe:
 *
 *   1. a refusal actually blocks the spend;
 *   2. an approval is bound to the recipient the contract named, so a third
 *      party cannot piggyback on it to redirect the funds;
 *   3. the vault cannot be drained by pointing a different contract at it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { rektVaultCode } from '../src/scenario.ts';
import { contractAddress, keyPairFromSeed, toHex } from '../src/crypto.ts';
import { callTx, deployTx, signInput, signTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { advance, pickUtxo, rig } from './helpers.ts';
import type { Blockchain } from '../src/chain.ts';

const GAS_LIMIT = 200_000;
const GAS_PRICE = 1n;
const GAS_BUDGET = BigInt(GAS_LIMIT) * GAS_PRICE;

function deployVault(unlockOffset: number, beneficiary: string) {
  const { chain, miner } = rig('covenant/miner');
  const owner = keyPairFromSeed('covenant/owner');

  // Fund the owner.
  const coin = pickUtxo(chain, miner.address);
  let fund = {
    version: 1 as const,
    kind: 'transfer' as const,
    inputs: [{ txid: coin.txid, vout: coin.vout, pubkey: '', signature: '', sequence: 0xffffffff }],
    outputs: [{ value: (coin.value - 1000n).toString(), address: owner.address }],
    lockTime: 0,
  };
  const signed = signTx(fund, miner, [{ value: coin.value, address: coin.address }]);
  let t = chain.tip.header.time + 600;
  assert.equal(chain.mineBlock([signed], miner.address, { time: t }).result.ok, true);

  const unlockHeight = chain.height + unlockOffset;
  const vaultAddress = contractAddress(owner.address, 0);
  const endowment = 5n * ZAPS_PER_DECKX;
  const ownerCoin = pickUtxo(chain, owner.address);

  let deploy = deployTx({
    inputs: [{ txid: ownerCoin.txid, vout: ownerCoin.vout }],
    outputs: [
      { value: endowment.toString(), address: vaultAddress },
      { value: (ownerCoin.value - endowment - GAS_BUDGET).toString(), address: owner.address },
    ],
    code: toHex(rektVaultCode(unlockHeight, beneficiary)),
    gasLimit: GAS_LIMIT,
    gasPrice: GAS_PRICE,
    nonce: 0,
  });
  deploy = signTx(deploy, owner, [{ value: ownerCoin.value, address: ownerCoin.address }]);

  t = chain.tip.header.time + 600;
  const res = chain.mineBlock([deploy], miner.address, { time: t });
  assert.deepEqual(res.rejected, []);
  assert.equal(res.result.ok, true, res.result.error);

  return { chain, miner, owner, vaultAddress, unlockHeight, endowment };
}

function release(
  chain: Blockchain,
  owner: ReturnType<typeof keyPairFromSeed>,
  vaultAddress: string,
  payTo: string,
  target = vaultAddress,
) {
  const vaultUtxo = chain.state.utxosFor(vaultAddress)[0];
  const gas = pickUtxo(chain, owner.address);
  let tx = callTx({
    inputs: [
      { txid: vaultUtxo.txid, vout: vaultUtxo.vout },
      { txid: gas.txid, vout: gas.vout },
    ],
    outputs: [
      { value: vaultUtxo.value.toString(), address: payTo },
      { value: (gas.value - GAS_BUDGET).toString(), address: owner.address },
    ],
    target,
    gasLimit: GAS_LIMIT,
    gasPrice: GAS_PRICE,
    nonce: chain.state.nonceOf(owner.address),
  });
  return signInput(tx, 1, owner, { value: gas.value, address: gas.address });
}

test('a covenant output is created as a real UTXO with no key behind it', () => {
  const beneficiary = keyPairFromSeed('covenant/carol').address;
  const { chain, vaultAddress, endowment } = deployVault(6, beneficiary);

  const utxos = chain.state.utxosFor(vaultAddress);
  assert.equal(utxos.length, 1);
  assert.equal(utxos[0].value, endowment);
  assert.equal(chain.state.balanceOf(vaultAddress), endowment);

  const account = chain.state.getContract(vaultAddress);
  assert.ok(account);
  assert.equal(account!.storage['1'] !== undefined, true, 'beneficiary must be stored');
  assert.equal(chain.auditSupply().balanced, true);
});

test('the covenant refuses a spend before its unlock height', () => {
  const beneficiary = keyPairFromSeed('covenant/carol').address;
  const { chain, owner, vaultAddress } = deployVault(6, beneficiary);

  const tx = release(chain, owner, vaultAddress, beneficiary);
  const res = chain.applyTransaction(tx, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /covenant refused/);
});

test('the covenant approves once the unlock height is reached', () => {
  const carol = keyPairFromSeed('covenant/carol');
  const { chain, miner, owner, vaultAddress, unlockHeight, endowment } = deployVault(4, carol.address);

  advance(chain, miner.address, unlockHeight - chain.height);
  assert.ok(chain.height >= unlockHeight);

  const tx = release(chain, owner, vaultAddress, carol.address);
  const t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([tx], miner.address, { time: t });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);

  assert.equal(chain.state.balanceOf(carol.address), endowment);
  assert.equal(chain.state.balanceOf(vaultAddress), 0n);
  assert.equal(chain.state.utxosFor(vaultAddress).length, 0);
  assert.equal(chain.auditSupply().balanced, true);

  // The spending input carried no signature at all.
  const spent = mined.block.transactions.find((x) => txid(x) === txid(tx))!;
  assert.equal(spent.inputs[0].signature, '');
  assert.equal(spent.inputs[0].pubkey, '');
});

test('an approval cannot be redirected to a different recipient', () => {
  const carol = keyPairFromSeed('covenant/carol');
  const mallory = keyPairFromSeed('covenant/mallory');
  const { chain, miner, owner, vaultAddress, unlockHeight } = deployVault(4, carol.address);

  advance(chain, miner.address, unlockHeight - chain.height);

  // Same approved call, but paying Mallory instead of the named beneficiary.
  const tx = release(chain, owner, vaultAddress, mallory.address);
  const res = chain.applyTransaction(tx, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /no output matches the authorised recipient/);
});

test('a covenant output cannot be spent by a plain transfer', () => {
  const carol = keyPairFromSeed('covenant/carol');
  const { chain, owner, vaultAddress } = deployVault(4, carol.address);
  const vaultUtxo = chain.state.utxosFor(vaultAddress)[0];

  let tx = {
    version: 1 as const,
    kind: 'transfer' as const,
    inputs: [{ txid: vaultUtxo.txid, vout: vaultUtxo.vout, pubkey: '', signature: '', sequence: 0xffffffff }],
    outputs: [{ value: (vaultUtxo.value - 1000n).toString(), address: owner.address }],
    lockTime: 0,
  };
  const signed = signTx(tx, owner, [{ value: vaultUtxo.value, address: vaultUtxo.address }]);

  const res = chain.applyTransaction(signed, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /requires a 'call' transaction/);
});

test('a covenant output cannot be unlocked by pointing at a different contract', () => {
  const carol = keyPairFromSeed('covenant/carol');
  const { chain, owner, vaultAddress } = deployVault(4, carol.address);

  // Target some other contract address — even a permissive one.
  const decoy = contractAddress(owner.address, 99);
  const tx = release(chain, owner, vaultAddress, carol.address, decoy);
  const res = chain.applyTransaction(tx, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /must target the locking contract/);
});

test('the vault counts every release attempt, approved or not', () => {
  const carol = keyPairFromSeed('covenant/carol');
  const { chain, miner, owner, vaultAddress, unlockHeight } = deployVault(4, carol.address);

  const before = chain.state.getContract(vaultAddress)!.storage['2'];
  advance(chain, miner.address, unlockHeight - chain.height);

  const tx = release(chain, owner, vaultAddress, carol.address);
  const t = chain.tip.header.time + 600;
  assert.equal(chain.mineBlock([tx], miner.address, { time: t }).result.ok, true);

  const after = chain.state.getContract(vaultAddress)!.storage['2'];
  assert.equal(Number(after), Number(before) + 1);
});
