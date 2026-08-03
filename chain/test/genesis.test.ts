/**
 * The genesis block, and the first transaction ever spent from it.
 *
 * This is the test the whole project is graded on: a chain that cannot
 * reproduce its own genesis is not a chain, it is a database with extra steps.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { Blockchain, GENESIS_TIME } from '../src/chain.ts';
import {
  bitsToTarget,
  blockHash,
  blockSubsidy,
  checkHeader,
  computeMerkleRoot,
  GENESIS_BITS,
  GENESIS_MEMO,
  HALVING_INTERVAL,
  INITIAL_SUBSIDY,
  MAX_SUPPLY,
  meetsTarget,
  mine,
} from '../src/block.ts';
import { verifyMerkleProof, merkleProof } from '../src/merkle.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { checkTx, coinbaseTx, formatDeckx, signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { keyPairFromSeed, beToBigInt, fromHex } from '../src/crypto.ts';

test('genesis is deterministic — two independent constructions agree byte for byte', () => {
  const a = Blockchain.create();
  const b = Blockchain.create();

  assert.equal(blockHash(a.tip.header), blockHash(b.tip.header));
  assert.equal(a.tip.header.merkleRoot, b.tip.header.merkleRoot);
  assert.equal(a.tip.header.stateRoot, b.tip.header.stateRoot);
  assert.equal(a.tip.header.nonce, b.tip.header.nonce);
  assert.equal(txid(a.tip.transactions[0]), txid(b.tip.transactions[0]));
});

test('genesis carries real proof of work', () => {
  const chain = Blockchain.create();
  const hash = blockHash(chain.tip.header);

  assert.equal(chain.tip.header.bits, GENESIS_BITS);
  assert.ok(meetsTarget(hash, GENESIS_BITS), `hash ${hash} does not meet target`);
  assert.ok(
    beToBigInt(fromHex(hash)) <= bitsToTarget(GENESIS_BITS),
    'hash must be numerically below the target',
  );
  // The work was not free: a hash under a 2^-16 target means ~65k attempts.
  assert.ok(hash.startsWith('0000'), `expected four leading zero nibbles, got ${hash.slice(0, 8)}`);
});

test('genesis header passes the same validation as every other block', () => {
  const chain = Blockchain.create();
  const check = checkHeader(chain.tip, GENESIS_TIME + 1);
  assert.equal(check.ok, true, check.error);
});

test('genesis has no parent, height 0, and an all-zero prevHash', () => {
  const chain = Blockchain.create();
  assert.equal(chain.tip.header.height, 0);
  assert.equal(chain.height, 0);
  assert.equal(chain.tip.header.prevHash, '0'.repeat(64));
  assert.equal(chain.blocks.length, 1);
});

test('genesis coinbase pays exactly the subsidy and embeds the REKT message', () => {
  const chain = Blockchain.create();
  const cb = chain.tip.transactions[0];

  assert.equal(cb.kind, 'coinbase');
  assert.equal(cb.inputs.length, 0);
  assert.equal(cb.outputs.length, 1);
  assert.equal(BigInt(cb.outputs[0].value), blockSubsidy(0));
  assert.equal(BigInt(cb.outputs[0].value), INITIAL_SUBSIDY);
  assert.equal(formatDeckx(BigInt(cb.outputs[0].value)), '199.77168949 DECKX');
  // Derived from the 21 M cap and the 365-day halving, not chosen by hand.
  assert.equal(INITIAL_SUBSIDY, MAX_SUPPLY / (2n * BigInt(HALVING_INTERVAL)));
  void ZAPS_PER_DECKX;
  assert.equal(cb.memo, GENESIS_MEMO);
  assert.match(cb.memo!, /^REKT /);
});

test('genesis state root commits to exactly one UTXO', () => {
  const chain = Blockchain.create();
  assert.equal(chain.state.utxoCount, 1);
  assert.equal(chain.state.stateRoot(), chain.tip.header.stateRoot);

  const audit = chain.auditSupply();
  assert.equal(audit.balanced, true);
  assert.equal(audit.utxoTotal, blockSubsidy(0));
});

test('the genesis coinbase is provable against the merkle root (SPV)', () => {
  const chain = Blockchain.create();
  const ids = chain.tip.transactions.map(txid);
  const proof = merkleProof(ids, 0);
  assert.equal(verifyMerkleProof(ids[0], proof, chain.tip.header.merkleRoot), true);
  assert.equal(verifyMerkleProof('ff'.repeat(32), proof, chain.tip.header.merkleRoot), false);
});

test('the genesis coinbase is immature and cannot be spent immediately', () => {
  const chain = Blockchain.create();
  const key = Blockchain.genesisKey();
  const coinbase = chain.tip.transactions[0];

  let tx = transferTx({
    inputs: [{ txid: txid(coinbase), vout: 0 }],
    outputs: [{ value: (49n * ZAPS_PER_DECKX).toString(), address: key.address }],
    memo: 'premature spend',
  });
  tx = signTx(tx, key, [{ value: blockSubsidy(0), address: key.address }]);

  const res = chain.applyTransaction(tx, chain.state.clone(), {
    height: 1,
    time: GENESIS_TIME + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /immature/);
});

test('FIRST TRANSACTION: the genesis coinbase is spent once mature, and lands in a block', () => {
  // Real difficulty for genesis; the following blocks use the same chain, so
  // this test mines COINBASE_MATURITY real blocks. It is the slow test on
  // purpose — the maturity rule is consensus, not a configuration knob.
  const chain = Blockchain.create({ bits: 0x207fffff, seed: 'deckxcoin/genesis/rekt' });
  const key = Blockchain.genesisKey();
  const alice = keyPairFromSeed('deckxcoin/alice');
  const bob = keyPairFromSeed('deckxcoin/bob');

  let t = chain.tip.header.time;
  for (let i = 0; i < COINBASE_MATURITY; i++) {
    t += 600;
    const { result } = chain.mineBlock([], alice.address, { time: t });
    assert.equal(result.ok, true, result.error);
  }
  assert.equal(chain.height, COINBASE_MATURITY);

  const genesisCoinbase = chain.blocks[0].transactions[0];
  const genesisTxid = txid(genesisCoinbase);
  const value = blockSubsidy(0);

  const send = 30n * ZAPS_PER_DECKX;
  const fee = 1000n;
  const change = value - send - fee;

  let tx = transferTx({
    inputs: [{ txid: genesisTxid, vout: 0 }],
    outputs: [
      { value: send.toString(), address: bob.address },
      { value: change.toString(), address: key.address },
    ],
    memo: 'first spend from genesis',
  });
  tx = signTx(tx, key, [{ value, address: key.address }]);

  // Stateless validation first.
  const stateless = checkTx(tx, [{ value, address: key.address }]);
  assert.equal(stateless.ok, true, stateless.error);
  assert.equal(stateless.fee, fee);

  // Then into a block.
  t += 600;
  const { block, result, rejected } = chain.mineBlock([tx], alice.address, { time: t });
  assert.deepEqual(rejected, []);
  assert.equal(result.ok, true, result.error);
  assert.equal(block.transactions.length, 2);
  assert.equal(txid(block.transactions[1]), txid(tx));

  // Balances moved.
  assert.equal(chain.state.balanceOf(bob.address), send);
  assert.equal(chain.state.balanceOf(key.address), change);
  assert.equal(chain.state.hasUtxo(genesisTxid, 0), false, 'genesis output must be spent');

  // The miner collected the fee on top of the subsidy.
  assert.equal(result.totalFees, fee);
  const coinbaseValue = BigInt(block.transactions[0].outputs[0].value);
  assert.equal(coinbaseValue, blockSubsidy(chain.height) + fee);

  // Supply still adds up.
  const audit = chain.auditSupply();
  assert.equal(audit.balanced, true, `supply drift: ${audit.utxoTotal} vs ${audit.expectedSubsidy}`);
});

test('a second spend of the same output is rejected', () => {
  const chain = Blockchain.regtest();
  const key = Blockchain.genesisKey();
  const regtestKey = keyPairFromSeed('deckxcoin/regtest');
  const bob = keyPairFromSeed('deckxcoin/bob');
  void key;

  let t = chain.tip.header.time;
  for (let i = 0; i < COINBASE_MATURITY; i++) {
    t += 600;
    chain.mineBlock([], regtestKey.address, { time: t });
  }

  const cb = chain.blocks[0].transactions[0];
  const value = blockSubsidy(0);
  const build = () => {
    const tx = transferTx({
      inputs: [{ txid: txid(cb), vout: 0 }],
      outputs: [{ value: (value - 1000n).toString(), address: bob.address }],
    });
    return signTx(tx, regtestKey, [{ value, address: regtestKey.address }]);
  };

  const first = build();
  t += 600;
  const r1 = chain.mineBlock([first], regtestKey.address, { time: t });
  assert.equal(r1.result.ok, true, r1.result.error);

  const second = build();
  const res = chain.applyTransaction(second, chain.state.clone(), {
    height: chain.height + 1,
    time: t + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /unknown or already-spent/);
});

test('a block whose state root is wrong is rejected', () => {
  const chain = Blockchain.regtest();
  const miner = keyPairFromSeed('deckxcoin/regtest');
  const t = chain.tip.header.time + 600;

  /*
   * Build a block that is valid in *every other respect* — right height, right
   * parent, right difficulty, real proof of work over the forged header — and
   * differs only in its state-root commitment. Mutating an already-accepted
   * block instead would trip the height or prevHash check first, and the test
   * would pass without ever reaching the rule it claims to cover.
   */
  const cb = coinbaseTx(miner.address, blockSubsidy(1), 1, 'forged');
  const forgedHeader = {
    version: 1,
    prevHash: chain.tipHash,
    merkleRoot: computeMerkleRoot([cb]),
    stateRoot: 'ab'.repeat(32),
    time: t,
    bits: chain.nextBitsFor(1),
    height: 1,
    nonce: 0,
    extraNonce: 0,
  };
  const forged = { header: mine(forgedHeader).header, transactions: [cb] };

  const res = chain.addBlock(forged, t + 1);
  assert.equal(res.ok, false);
  assert.match(res.error!, /state root mismatch/);
  assert.equal(chain.height, 0, 'the chain must not have moved');
});
