/**
 * Volt watchtower.
 *
 * Two properties are being tested, and the privacy one matters as much as the
 * security one. A tower that catches every breach but learns everyone's
 * payment graph is not a component anyone should run for strangers.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { Blockchain } from '../src/chain.ts';
import { keyPairFromSeed, toHex } from '../src/crypto.ts';
import { txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { VoltNetwork } from '../src/volt/network.ts';
import {
  backfill,
  blobForRevokedState,
  DEFAULT_FEE_LADDER,
  HINT_BYTES,
  ladderForRevokedState,
  openBlob,
  sealBlob,
  Watchtower,
} from '../src/volt/watchtower.ts';
import { ChainStore } from '../src/store/sqlite.ts';
import { advance, pickUtxo, rig } from './helpers.ts';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DECKX = ZAPS_PER_DECKX;

const dirs: string[] = [];

/** A throwaway on-disk store, so persistence is tested against real SQLite. */
function tempStore(): ChainStore {
  const dir = mkdtempSync(join(tmpdir(), 'deckx-tower-'));
  dirs.push(dir);
  return new ChainStore(join(dir, 'tower.sqlite'));
}

test.after(() => {
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* Windows may still hold the WAL; a leaked temp dir is harmless. */
    }
  }
});

/** A confirmed channel with some payment history. */
function channelWithHistory(capacity = 2n * DECKX, pushToB = 50_000_000n) {
  const { chain, miner } = rig('tower/miner');
  const net = new VoltNetwork();
  const alice = net.addNode('alice', 'tower/alice');
  const bob = net.addNode('bob', 'tower/bob');

  const funding = pickUtxo(chain, miner.address);
  const opened = net.openChannel({
    a: alice,
    b: bob,
    capacity,
    funding,
    funderKey: miner,
    changeAddress: miner.address,
    pushToB,
  });

  const t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([opened.fundingTx], miner.address, { time: t });
  assert.equal(mined.result.ok, true, mined.result.error);
  net.confirmAll(chain);

  // Several payments, so there are revoked states worth stealing from.
  opened.channel.pay('a', 60_000_000n);
  opened.channel.pay('a', 20_000_000n);
  opened.channel.pay('b', 5_000_000n);

  return { chain, miner, net, alice, bob, ...opened };
}

/* ──────────────────────────────────────────────────── blob crypto ── */

test('a blob round-trips only for someone who knows the full commitment txid', () => {
  const { channel } = channelWithHistory();
  const commitment = channel.history[1].forA;
  const id = txid(commitment);
  const penalty = channel.penaltyFor(commitment, 1, 'a', channel.b.key.address);

  const blob = sealBlob(id, penalty, 1, 1000n);

  // The hint is genuinely only half the identifier.
  assert.equal(blob.hint.length, HINT_BYTES * 2);
  assert.equal(blob.hint, id.slice(0, HINT_BYTES * 2));
  assert.notEqual(blob.payload, '');

  const opened = openBlob(id, blob);
  assert.ok(opened, 'the holder of the full txid can open it');
  assert.equal(txid(opened!), txid(penalty));
});

test('the hint alone does not open a blob', () => {
  const { channel } = channelWithHistory();
  const commitment = channel.history[1].forA;
  const id = txid(commitment);
  const penalty = channel.penaltyFor(commitment, 1, 'a', channel.b.key.address);
  const blob = sealBlob(id, penalty, 1, 1000n);

  // Everything the tower stores, plus a guess at the rest of the txid.
  const guess = blob.hint + '0'.repeat(64 - blob.hint.length);
  assert.equal(openBlob(guess, blob), undefined, 'a wrong key must fail the MAC, not decrypt garbage');

  const nearMiss = id.slice(0, 63) + (id.endsWith('a') ? 'b' : 'a');
  assert.equal(openBlob(nearMiss, blob), undefined);
});

test('a tampered blob fails its MAC instead of yielding a broken transaction', () => {
  const { channel } = channelWithHistory();
  const commitment = channel.history[1].forA;
  const id = txid(commitment);
  const penalty = channel.penaltyFor(commitment, 1, 'a', channel.b.key.address);
  const blob = sealBlob(id, penalty, 1, 1000n);

  const bytes = [...blob.payload];
  bytes[10] = bytes[10] === 'a' ? 'b' : 'a';
  const tampered = { ...blob, payload: bytes.join('') };

  assert.equal(openBlob(id, tampered), undefined);
});

/* ──────────────────────────────────────────────────── tower logic ── */

test('the tower stores blobs it cannot read', () => {
  const { channel } = channelWithHistory();
  const tower = new Watchtower({ broadcast: () => true });

  const registered = backfill(tower, channel, 'a', channel.b.key.address);
  assert.ok(registered >= 3, `expected several revoked states, registered ${registered}`);
  assert.equal(tower.hintCount, registered);

  // Everything a tower receives is opaque. Inspect the wire form of each blob:
  // no address, no amount, no channel id, and only half of the txid.
  for (let n = 0; n < channel.commitmentNumber; n++) {
    const blob = blobForRevokedState(channel, n, 'a', channel.b.key.address);
    if (!blob) continue;
    // `fee` is a bigint and deliberately not encrypted — see the note in
    // `sealBlob`. Serialise it as a string so the leak check can run.
    const wire = JSON.stringify(blob, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));

    assert.equal(wire.includes(channel.a.key.address), false, 'blob leaks the cheater address');
    assert.equal(wire.includes(channel.b.key.address), false, 'blob leaks the victim address');
    assert.equal(wire.includes(channel.id), false, 'blob leaks the channel id');
    assert.equal(wire.includes(channel.capacity.toString()), false, 'blob leaks the capacity');

    // The hint is exactly half the commitment txid — not enough to derive the key.
    const commitmentId = txid(channel.history[n].forA);
    assert.equal(blob.hint, commitmentId.slice(0, HINT_BYTES * 2));
    assert.equal(wire.includes(commitmentId), false, 'blob must never carry the full txid');
  }
});

test('duplicate registrations are ignored', () => {
  const { channel } = channelWithHistory();
  const tower = new Watchtower({ broadcast: () => true });
  const blob = blobForRevokedState(channel, 1, 'a', channel.b.key.address)!;

  tower.register(blob);
  tower.register(blob);
  tower.register(blob);
  assert.equal(tower.blobCount, 1);
});

test('scanning an honest block finds nothing', () => {
  const { chain, channel } = channelWithHistory();
  const tower = new Watchtower({ broadcast: () => true });
  backfill(tower, channel, 'a', channel.b.key.address);

  for (let h = 0; h <= chain.height; h++) {
    const found = tower.scanBlock(chain.blocks[h]);
    assert.deepEqual(found, [], `block ${h} should not look like a breach`);
  }
  assert.equal(tower.breaches.length, 0);
  assert.ok(tower.scannedBlocks > 0);
});

/* ────────────────────────────────────────────────── the whole point ── */

test('WATCHTOWER: a breach is caught and punished while the victim is offline', () => {
  const { chain, miner, channel } = channelWithHistory();

  // Bob hires a tower before going offline. The tower broadcasts by mining,
  // which is what a real one would delegate to its node.
  const broadcast: string[] = [];
  const tower = new Watchtower({
    broadcast: (tx) => {
      broadcast.push(txid(tx));
      const t = chain.tip.header.time + 600;
      const res = chain.mineBlock([tx], miner.address, { time: t });
      return res.result.ok && res.rejected.length === 0;
    },
  });
  const registered = backfill(tower, channel, 'a', channel.b.key.address);
  assert.ok(registered >= 3);

  // Alice cheats with a state where she held far more.
  const revokedNumber = 1;
  const stale = channel.history[revokedNumber].forA;
  // Alice's own output is the revocable one; bob's is the plain to_remote.
  const aliceOutput = BigInt(stale.outputs.find((o) => o.script?.type === 'revocable')!.value);
  const bobOutput = BigInt(stale.outputs.find((o) => !o.script)!.value);

  let t = chain.tip.header.time + 600;
  const cheat = chain.mineBlock([stale], miner.address, { time: t });
  assert.deepEqual(cheat.rejected, []);
  assert.equal(cheat.result.ok, true, cheat.result.error);

  const balancesBefore = {
    alice: chain.state.balanceOf(channel.a.key.address),
    bob: chain.state.balanceOf(channel.b.key.address),
  };
  assert.ok(balancesBefore.alice > 0n, 'the stale commitment paid alice on-chain');

  // Bob is offline. The tower scans the block and acts.
  const found = tower.scanBlock(cheat.block);

  assert.equal(found.length, 1, 'the tower must recognise the revoked commitment');
  assert.equal(found[0].commitmentTxid, txid(stale));
  assert.equal(found[0].height, cheat.block.header.height);
  assert.equal(broadcast.length, 1);

  /*
   * Alice keeps nothing. Bob's balance already contained his own to_remote
   * output from the stale commitment, so the penalty converts (his output +
   * her output) into a single sweep — his net gain is *her* output, less fee.
   */
  assert.equal(chain.state.balanceOf(channel.a.key.address), 0n, 'the cheater keeps nothing');
  assert.equal(
    chain.state.balanceOf(channel.b.key.address),
    balancesBefore.bob - bobOutput + (aliceOutput + bobOutput) - 1000n,
    'bob swept both outputs, less the penalty fee',
  );
  assert.equal(found[0].sweptZaps, aliceOutput + bobOutput - 1000n);
  assert.equal(chain.auditSupply().balanced, true);

  /*
   * The tower keeps the blobs and marks the breach pending. It does not forget
   * until it has confirmation the penalty landed — dropping them on broadcast
   * would leave nothing to escalate with if the penalty never confirms.
   */
  assert.equal(tower.hintCount, registered, 'blobs are retained until the penalty confirms');
  assert.equal(tower.pendingCount, 1);
  assert.equal(tower.stats().breachesCaught, 1);
  assert.equal(found[0].rung, 0, 'the cheapest rung is tried first');
  assert.equal(found[0].fee, 1_000n);
  void t;
});

test('WATCHTOWER: an honest force-close is not punished', () => {
  const { chain, miner, channel } = channelWithHistory();
  const tower = new Watchtower({
    broadcast: () => assert.fail('must not broadcast on an honest close'),
  });
  backfill(tower, channel, 'a', channel.b.key.address);

  // Alice force-closes with the *current* state, which is legitimate.
  const latest = channel.forceClose('a');
  const t = chain.tip.header.time + 600;
  const closed = chain.mineBlock([latest], miner.address, { time: t });
  assert.equal(closed.result.ok, true, closed.result.error);

  const found = tower.scanBlock(closed.block);
  assert.deepEqual(found, [], 'the latest commitment is not a breach');
  assert.equal(tower.breaches.length, 0);
});

test('a tower whose broadcast fails climbs the ladder, then keeps the blobs', () => {
  const { chain, miner, channel } = channelWithHistory();
  const attempted: bigint[] = [];
  const tower = new Watchtower({
    broadcast: (_tx, fee) => {
      attempted.push(fee);
      return false; // e.g. the node is unreachable
    },
  });
  const registered = backfill(tower, channel, 'a', channel.b.key.address);

  const stale = channel.history[1].forA;
  const t = chain.tip.header.time + 600;
  const cheat = chain.mineBlock([stale], miner.address, { time: t });

  const found = tower.scanBlock(cheat.block);
  assert.deepEqual(found, [], 'a failed broadcast is not a caught breach');

  // Every rung of the ladder was tried, cheapest first, before giving up.
  assert.deepEqual(attempted, [...DEFAULT_FEE_LADDER]);
  assert.equal(tower.hintCount, registered, 'the blobs must survive for a retry');
  assert.equal(tower.pendingCount, 0, 'nothing is pending when nothing was broadcast');
});

/* ─────────────────────────────────────────────── fee ladder + retry ── */

test('a ladder seals the same penalty at several fee levels', () => {
  const { channel } = channelWithHistory();
  const ladder = ladderForRevokedState(channel, 1, 'a', channel.b.key.address);

  assert.equal(ladder.length, DEFAULT_FEE_LADDER.length);
  assert.deepEqual(ladder.map((b) => b.fee), [...DEFAULT_FEE_LADDER]);

  // Same commitment, so the same hint — the tower groups them without knowing why.
  const hints = new Set(ladder.map((b) => b.hint));
  assert.equal(hints.size, 1);

  // Each rung decrypts to a penalty that sweeps correspondingly less.
  const commitmentId = txid(channel.history[1].forA);
  const swept = ladder.map((b) => {
    const penalty = openBlob(commitmentId, b)!;
    return penalty.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  });
  for (let i = 1; i < swept.length; i++) {
    assert.ok(swept[i] < swept[i - 1], 'a higher fee must leave less to sweep');
    assert.equal(swept[i - 1] - swept[i], ladder[i].fee - ladder[i - 1].fee);
  }
});

test('a fee rung larger than the swept value is not sealed', () => {
  const { channel } = channelWithHistory();
  // Second rung exceeds the entire channel, so the ladder stops after the first.
  const ladder = ladderForRevokedState(channel, 1, 'a', channel.b.key.address, [
    1_000n,
    100n * DECKX,
  ]);
  assert.equal(ladder.length, 1, 'an unprofitable penalty must not be sealed');
});

test('RETRY: an unconfirmed penalty is re-broadcast one rung higher', () => {
  const { chain, miner, channel } = channelWithHistory();

  const attempted: bigint[] = [];
  let confirmedTxid: string | undefined;

  const tower = new Watchtower({
    retryAfterBlocks: 2,
    // The first two broadcasts are accepted for relay but never confirm; the
    // third lands. This is a fee spike, seen from the tower's side.
    broadcast: (tx, fee) => {
      attempted.push(fee);
      if (attempted.length < 3) return true;
      const t = chain.tip.header.time + 600;
      const res = chain.mineBlock([tx], miner.address, { time: t });
      if (res.result.ok && res.rejected.length === 0) confirmedTxid = txid(tx);
      return res.result.ok && res.rejected.length === 0;
    },
    isConfirmed: (id) => id === confirmedTxid,
  });
  backfill(tower, channel, 'a', channel.b.key.address);

  // Alice cheats.
  let t = chain.tip.header.time + 600;
  const cheat = chain.mineBlock([channel.history[1].forA], miner.address, { time: t });
  const first = tower.scanBlock(cheat.block);
  assert.equal(first.length, 1);
  assert.equal(first[0].rung, 0, 'the cheapest rung goes first');
  assert.equal(tower.pendingCount, 1);

  /*
   * Blocks pass with no confirmation and the tower escalates. It only *learns*
   * a penalty landed on the scan after it did, so the loop keeps going past
   * the confirming broadcast — that extra pass is what clears the pending
   * entry, and it is how a real tower behaves too.
   */
  for (let i = 0; i < 8 && tower.pendingCount > 0; i++) {
    t = chain.tip.header.time + 600;
    const { block } = chain.mineBlock([], miner.address, { time: t });
    tower.scanBlock(block);
  }

  assert.ok(attempted.length >= 3, `expected escalation, only ${attempted.length} attempts`);
  assert.deepEqual(attempted.slice(0, 3), [1_000n, 4_000n, 16_000n], 'fees must climb');
  assert.ok(tower.escalations >= 1);

  // Once it confirms, the tower forgets the channel.
  assert.equal(tower.pendingCount, 0, 'a confirmed penalty clears the pending entry');
  assert.equal(chain.state.balanceOf(channel.a.key.address), 0n, 'the cheater still keeps nothing');
  assert.equal(chain.auditSupply().balanced, true);
});

/* ────────────────────────────────────────────────────── persistence ── */

test('PERSISTENCE: a restarted tower still protects the channel', () => {
  const { chain, miner, channel } = channelWithHistory();
  const store = tempStore();

  // A tower hired before the restart.
  const before = new Watchtower({ broadcast: () => true, store });
  const covered = backfill(before, channel, 'a', channel.b.key.address);
  assert.ok(covered >= 3);
  assert.ok(before.blobCount >= covered * 2, 'each commitment stored a ladder');
  assert.equal(store.watchBlobCount, before.blobCount, 'blobs reached the database');

  // The process dies. A new tower opens the same database.
  const broadcast: string[] = [];
  const after = new Watchtower({
    store,
    broadcast: (tx) => {
      broadcast.push(txid(tx));
      const t = chain.tip.header.time + 600;
      const res = chain.mineBlock([tx], miner.address, { time: t });
      return res.result.ok && res.rejected.length === 0;
    },
  });

  assert.equal(after.hintCount, before.hintCount, 'the index was rehydrated');
  assert.equal(after.blobCount, before.blobCount);
  assert.equal(after.stats().persistent, true);

  // And it still catches the breach.
  const stale = channel.history[1].forA;
  const t = chain.tip.header.time + 600;
  const cheat = chain.mineBlock([stale], miner.address, { time: t });
  const found = after.scanBlock(cheat.block);

  assert.equal(found.length, 1, 'a restarted tower must still punish a breach');
  assert.equal(broadcast.length, 1);
  assert.equal(chain.state.balanceOf(channel.a.key.address), 0n);
  assert.equal(chain.auditSupply().balanced, true);
});

test('forgetting a channel removes it from the database too', () => {
  const { channel } = channelWithHistory();
  const store = tempStore();
  const tower = new Watchtower({ broadcast: () => true, store });

  const ladder = ladderForRevokedState(channel, 1, 'a', channel.b.key.address);
  tower.registerLadder(ladder);
  assert.equal(store.watchBlobCount, ladder.length);

  tower.forget(ladder[0].hint);
  assert.equal(store.watchBlobCount, 0, 'a forgotten channel must not linger on disk');
  assert.equal(tower.blobCount, 0);
});

test('the database is as blind as the tower', () => {
  const { channel } = channelWithHistory();
  const store = tempStore();
  const tower = new Watchtower({ broadcast: () => true, store });
  backfill(tower, channel, 'a', channel.b.key.address);

  // Everything the database holds, as text.
  const dumped = store
    .watchHints()
    .flatMap((hint) => store.watchBlobs(hint))
    .map((row) => JSON.stringify(row))
    .join('\n');

  assert.ok(dumped.length > 0, 'the dump must not be empty, or this proves nothing');
  assert.equal(dumped.includes(channel.a.key.address), false);
  assert.equal(dumped.includes(channel.b.key.address), false);
  assert.equal(dumped.includes(channel.id), false);
  assert.equal(dumped.includes(channel.funding.txid), false);
});

test('a channel can be forgotten after a cooperative close', () => {
  const { channel } = channelWithHistory();
  const tower = new Watchtower({ broadcast: () => true });
  const blob = blobForRevokedState(channel, 1, 'a', channel.b.key.address)!;
  tower.register(blob);

  assert.equal(tower.forget(blob.hint), true);
  assert.equal(tower.forget(blob.hint), false);
  assert.equal(tower.blobCount, 0);
});

void advance;
void Blockchain;
void keyPairFromSeed;
void toHex;
void COINBASE_MATURITY;
