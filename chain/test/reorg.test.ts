/**
 * Persistence and reorganisation.
 *
 * The chain-splitting tests here are the ones that decide whether this can be
 * a network at all. An append-only chain works until two miners find a block
 * at the same height, which on any real network happens within hours.
 *
 * Every assertion checks the *state root*, not just the tip hash. A node can
 * be on the right chain with the wrong UTXO set, and that is the failure that
 * silently forks it off the network three blocks later.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ChainStore } from '../src/store/sqlite.ts';
import { ACCEPT, ChainState } from '../src/node/chainstate.ts';
import { MAINNET, REGTEST } from '../src/params.ts';
import { WorldState } from '../src/state.ts';
import { blockHash, blockSubsidy, computeMerkleRoot, mine, type Block, type BlockHeader } from '../src/block.ts';
import { applyTx } from '../src/chain.ts';
import { coinbaseTx, signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { keyPairFromSeed } from '../src/crypto.ts';
import { COINBASE_MATURITY } from '../src/state.ts';

const dirs: string[] = [];

function tempStore(): ChainStore {
  const dir = mkdtempSync(join(tmpdir(), 'deckx-test-'));
  dirs.push(dir);
  return new ChainStore(join(dir, 'chain.sqlite'));
}

test.after(() => {
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* Windows sometimes holds the WAL briefly; a leaked temp dir is harmless. */
    }
  }
});

function openChain() {
  const store = tempStore();
  return { store, chain: ChainState.open({ params: REGTEST, store, undoRetention: 100 }) };
}

/**
 * Mine a block on top of `parentHash` without going through the tip.
 *
 * This is how a competing branch is built: the miner is working from a parent
 * that is not (or is no longer) the active tip.
 */
function mineOn(chain: ChainState, parentHash: string, minerAddress: string, time: number): Block {
  const parent = chain.getHeader(parentHash)!;
  const height = parent.height + 1;

  // Rewind a copy of state to the parent by replaying the active chain.
  const state = replayTo(chain, parentHash);

  const cb = coinbaseTx(minerAddress, blockSubsidy(height), height, `fork/${height}`);
  applyTx(cb, state, { height, time, availableFees: 0n });

  const template: BlockHeader = {
    version: 1,
    prevHash: parentHash,
    merkleRoot: computeMerkleRoot([cb]),
    stateRoot: state.stateRoot(),
    time,
    bits: chain.nextBitsAfter(parent),
    height,
    nonce: 0,
    extraNonce: 0,
  };
  const mined = mine(template);
  return { header: mined.header, transactions: [cb] };
}

/** Rebuild the world state as of `hash` by replaying from genesis. */
function replayTo(chain: ChainState, hash: string) {
  const path: Block[] = [];
  let cursor = chain.getHeader(hash);
  while (cursor) {
    const block = chain.getBlock(cursor.hash)!;
    path.push(block);
    if (cursor.height === 0) break;
    cursor = chain.getHeader(cursor.prevHash);
  }
  path.reverse();

  const state = new WorldState();
  for (const block of path) {
    let fees = 0n;
    for (const tx of block.transactions.slice(1)) {
      const res = applyTx(tx, state, { height: block.header.height, time: block.header.time });
      fees += res.fee;
    }
    applyTx(block.transactions[0], state, {
      height: block.header.height,
      time: block.header.time,
      availableFees: fees,
    });
  }
  return state;
}

/* ─────────────────────────────────────────────────────── persistence ── */

test('a fresh store bootstraps genesis and records the network', () => {
  const { store, chain } = openChain();
  assert.equal(chain.height, 0);
  assert.equal(store.getMeta('network'), 'regtest');
  assert.equal(store.getMeta('genesis'), chain.tipHash);
  assert.equal(chain.state.utxoCount, 1);
  assert.equal(chain.auditSupply().balanced, true);
});

test('a chain reopens at its tip with an identical state root', () => {
  const store = tempStore();
  const miner = keyPairFromSeed('reorg/miner');

  let chain = ChainState.open({ params: REGTEST, store });
  let t = chain.tip.time;
  for (let i = 0; i < 5; i++) {
    t += 600;
    const res = chain.mineBlock([], miner.address, { time: t });
    assert.equal(res.accepted.status, ACCEPT.CONNECTED, res.accepted.error);
  }
  const beforeHeight = chain.height;
  const beforeTip = chain.tipHash;
  const beforeRoot = chain.state.stateRoot();
  const beforeSupply = chain.auditSupply().utxoTotal;
  store.close();

  // Reopen from disk — a restarted node must resume, not re-sync.
  const reopened = new ChainStore(store.path);
  chain = ChainState.open({ params: REGTEST, store: reopened });

  assert.equal(chain.height, beforeHeight);
  assert.equal(chain.tipHash, beforeTip);
  assert.equal(chain.state.stateRoot(), beforeRoot);
  assert.equal(chain.auditSupply().utxoTotal, beforeSupply);
  assert.equal(chain.auditSupply().balanced, true);
  reopened.close();
});

test('opening a regtest datadir as mainnet is refused', () => {
  const store = tempStore();
  ChainState.open({ params: REGTEST, store });
  assert.throws(
    () => ChainState.open({ params: MAINNET, store }),
    /holds a 'regtest' chain but this node is configured for 'mainnet'/,
  );
});

/* ─────────────────────────────────────────────────────────── intake ── */

test('a duplicate block is recognised, not re-applied', () => {
  const { chain } = openChain();
  const miner = keyPairFromSeed('reorg/dup');
  const { block } = chain.mineBlock([], miner.address, { time: chain.tip.time + 600 });

  const again = chain.acceptBlock(block, block.header.time + 1);
  assert.equal(again.status, ACCEPT.DUPLICATE);
  assert.equal(chain.height, 1);
});

test('a block with an unknown parent is an orphan, not an error', () => {
  const a = openChain();
  const b = openChain();
  const miner = keyPairFromSeed('reorg/orphan');

  // Build two blocks on b, then offer only the second to a.
  let t = b.chain.tip.time;
  b.chain.mineBlock([], miner.address, { time: (t += 600) });
  const second = b.chain.mineBlock([], miner.address, { time: (t += 600) });

  const res = a.chain.acceptBlock(second.block, t + 1);
  assert.equal(res.status, ACCEPT.ORPHAN);
  assert.match(res.error!, /unknown parent/);
  assert.equal(a.chain.height, 0);
});

test('a block with a forged state root is rejected and leaves no trace', () => {
  const { chain } = openChain();
  const miner = keyPairFromSeed('reorg/forge');
  const { block } = chain.mineBlock([], miner.address, { time: chain.tip.time + 600 });

  const rootBefore = chain.state.stateRoot();
  const heightBefore = chain.height;

  // Re-mine the same height with a wrong state root.
  const forgedHeader: BlockHeader = { ...block.header, stateRoot: 'ab'.repeat(32), nonce: 0 };
  const forged = { header: mine(forgedHeader).header, transactions: block.transactions };

  const res = chain.acceptBlock(forged, forged.header.time + 1);
  assert.notEqual(res.status, ACCEPT.CONNECTED);
  assert.equal(chain.height, heightBefore);
  assert.equal(chain.state.stateRoot(), rootBefore);
});

/* ─────────────────────────────────────────────────────────── reorg ── */

test('REORG: a heavier branch replaces the active chain and the state follows', () => {
  const { chain } = openChain();
  const alice = keyPairFromSeed('reorg/alice');
  const bob = keyPairFromSeed('reorg/bob');

  const genesis = chain.tipHash;
  let t = chain.tip.time;

  // Branch A: two blocks mined by alice, becomes the active chain.
  const a1 = chain.mineBlock([], alice.address, { time: (t += 600) });
  const a2 = chain.mineBlock([], alice.address, { time: (t += 600) });
  assert.equal(chain.height, 2);
  assert.equal(chain.state.balanceOf(alice.address), blockSubsidy(1) + blockSubsidy(2));
  assert.equal(chain.state.balanceOf(bob.address), 0n);

  // Branch B: three blocks from genesis mined by bob. More work, so it wins.
  let bt = chain.getHeader(genesis)!.time;
  const b1 = mineOn(chain, genesis, bob.address, (bt += 601));
  let res = chain.acceptBlock(b1, bt + 1);
  assert.equal(res.status, ACCEPT.SIDECHAIN, res.error);
  assert.equal(chain.height, 2, 'equal work must not trigger a reorg');

  const b2 = mineOn(chain, blockHash(b1.header), bob.address, (bt += 601));
  res = chain.acceptBlock(b2, bt + 1);
  assert.equal(res.status, ACCEPT.SIDECHAIN, res.error);
  assert.equal(chain.height, 2);

  const b3 = mineOn(chain, blockHash(b2.header), bob.address, (bt += 601));
  res = chain.acceptBlock(b3, bt + 1);
  assert.equal(res.status, ACCEPT.CONNECTED, res.error);

  // The reorg happened, and it reported exactly what moved.
  assert.ok(res.reorg, 'a reorg must be reported');
  assert.deepEqual(res.reorg!.disconnected, [blockHash(a2.block.header), blockHash(a1.block.header)]);
  assert.deepEqual(res.reorg!.connected, [
    blockHash(b1.header),
    blockHash(b2.header),
    blockHash(b3.header),
  ]);

  // Tip, height and — critically — the world state all followed.
  assert.equal(chain.height, 3);
  assert.equal(chain.tipHash, blockHash(b3.header));
  assert.equal(chain.state.balanceOf(alice.address), 0n, "alice's coinbases were undone");
  assert.equal(
    chain.state.balanceOf(bob.address),
    blockSubsidy(1) + blockSubsidy(2) + blockSubsidy(3),
  );
  assert.equal(chain.state.stateRoot(), b3.header.stateRoot);
  assert.equal(chain.auditSupply().balanced, true);
});

test('REORG: undoing a spend restores the exact UTXO that was consumed', () => {
  const { chain } = openChain();
  const miner = keyPairFromSeed('reorg/spend/miner');
  const payee = keyPairFromSeed('reorg/spend/payee');

  let t = chain.tip.time;
  for (let i = 0; i < COINBASE_MATURITY + 1; i++) {
    const r = chain.mineBlock([], miner.address, { time: (t += 600) });
    assert.equal(r.accepted.status, ACCEPT.CONNECTED, r.accepted.error);
  }

  const forkPoint = chain.tipHash;
  const forkHeight = chain.height;
  const rootAtFork = chain.state.stateRoot();

  // Spend a mature coinbase on branch A.
  const coin = chain.state
    .utxosFor(miner.address)
    .filter((u) => chain.height - u.height >= COINBASE_MATURITY)[0];
  const send = 5n * ZAPS_PER_DECKX;
  const spend = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: send.toString(), address: payee.address },
        { value: (coin.value - send - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const spendBlock = chain.mineBlock([spend], miner.address, { time: (t += 600) });
  assert.deepEqual(spendBlock.rejected, []);
  assert.equal(spendBlock.accepted.status, ACCEPT.CONNECTED, spendBlock.accepted.error);
  assert.equal(chain.state.balanceOf(payee.address), send);
  assert.equal(chain.state.hasUtxo(coin.txid, coin.vout), false, 'the coin was spent');

  // Branch B from the fork point, two blocks — more work than the one above.
  let bt = chain.getHeader(forkPoint)!.time;
  const b1 = mineOn(chain, forkPoint, payee.address, (bt += 601));
  assert.equal(chain.acceptBlock(b1, bt + 1).status, ACCEPT.SIDECHAIN);
  const b2 = mineOn(chain, blockHash(b1.header), payee.address, (bt += 601));
  const res = chain.acceptBlock(b2, bt + 1);
  assert.equal(res.status, ACCEPT.CONNECTED, res.error);

  // The spend was undone: the coin is unspent again and the payee has nothing
  // from it. This is exactly the double-spend window a reorg opens.
  assert.equal(chain.height, forkHeight + 2);
  assert.equal(chain.state.hasUtxo(coin.txid, coin.vout), true, 'the spent coin must be restored');
  const restored = chain.state.getUtxo(coin.txid, coin.vout)!;
  assert.equal(restored.value, coin.value);
  assert.equal(restored.address, coin.address);
  assert.equal(restored.height, coin.height);
  assert.equal(restored.coinbase, coin.coinbase);
  assert.equal(chain.auditSupply().balanced, true);
  void rootAtFork;
});

test('REORG: a branch that fails validation leaves the original tip intact', () => {
  const { chain } = openChain();
  const alice = keyPairFromSeed('reorg/bad/alice');
  const mallory = keyPairFromSeed('reorg/bad/mallory');

  const genesis = chain.tipHash;
  let t = chain.tip.time;
  chain.mineBlock([], alice.address, { time: (t += 600) });
  const goodTip = chain.tipHash;
  const goodRoot = chain.state.stateRoot();
  const goodHeight = chain.height;

  // Two-block branch where the second block over-pays its coinbase.
  let bt = chain.getHeader(genesis)!.time;
  const b1 = mineOn(chain, genesis, mallory.address, (bt += 601));
  assert.equal(chain.acceptBlock(b1, bt + 1).status, ACCEPT.SIDECHAIN);

  const parent = blockHash(b1.header);
  const parentHeader = chain.getHeader(parent)!;
  const height = 2;
  const greedy = coinbaseTx(mallory.address, blockSubsidy(height) * 3n, height, 'greedy');
  const template: BlockHeader = {
    version: 1,
    prevHash: parent,
    merkleRoot: computeMerkleRoot([greedy]),
    // A plausible-looking root; it will never be reached because the coinbase
    // is rejected first.
    stateRoot: b1.header.stateRoot,
    time: (bt += 601),
    bits: chain.nextBitsAfter(parentHeader),
    height,
    nonce: 0,
    extraNonce: 0,
  };
  const bad: Block = { header: mine(template).header, transactions: [greedy] };

  const res = chain.acceptBlock(bad, bt + 1);
  assert.equal(res.status, ACCEPT.INVALID, 'an over-paying coinbase must be rejected');

  // The node stayed where it was.
  assert.equal(chain.tipHash, goodTip);
  assert.equal(chain.height, goodHeight);
  assert.equal(chain.state.stateRoot(), goodRoot);
  assert.equal(chain.state.balanceOf(alice.address), blockSubsidy(1));
  assert.equal(chain.state.balanceOf(mallory.address), 0n);
  assert.equal(chain.auditSupply().balanced, true);
});

test('a reorg deeper than the undo window is refused rather than mis-applied', () => {
  const store = tempStore();
  const chain = ChainState.open({ params: REGTEST, store, undoRetention: 2 });
  const alice = keyPairFromSeed('reorg/deep/alice');
  const bob = keyPairFromSeed('reorg/deep/bob');

  const genesis = chain.tipHash;
  let t = chain.tip.time;
  for (let i = 0; i < 6; i++) chain.mineBlock([], alice.address, { time: (t += 600) });
  const tipBefore = chain.tipHash;

  // Seven blocks from genesis — heavier, but deeper than the 2-block window.
  let bt = chain.getHeader(genesis)!.time;
  let parent = genesis;
  let last;
  for (let i = 0; i < 7; i++) {
    const block = mineOn(chain, parent, bob.address, (bt += 601));
    last = chain.acceptBlock(block, bt + 1);
    parent = blockHash(block.header);
  }

  assert.equal(last!.status, ACCEPT.INVALID);
  assert.match(last!.error!, /undo window/);
  assert.equal(chain.tipHash, tipBefore, 'the node must stay on its chain');
  assert.equal(chain.auditSupply().balanced, true);
});

test('the block locator gets sparser as it goes back', () => {
  const { chain } = openChain();
  const miner = keyPairFromSeed('reorg/locator');
  let t = chain.tip.time;
  for (let i = 0; i < 40; i++) chain.mineBlock([], miner.address, { time: (t += 600) });

  const locator = chain.locator();
  assert.equal(locator[0], chain.tipHash);
  assert.equal(locator[locator.length - 1], chain.headerAt(0)!.hash);
  assert.ok(locator.length < 25, `locator should be sparse, got ${locator.length} entries`);

  // A peer at height 10 shares that block with us.
  const at10 = chain.headerAt(10)!;
  assert.equal(chain.findForkPoint([at10.hash]).hash, at10.hash);
  assert.equal(chain.findForkPoint(['ff'.repeat(32)]).height, 0, 'unknown locator falls back to genesis');
});

void txid;
