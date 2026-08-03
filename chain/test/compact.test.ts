/**
 * Compact block relay.
 *
 * The interesting cases are the ones where reconstruction *fails*: a peer
 * missing a transaction, a short-id collision, a malformed announcement. A
 * relay scheme that only works when both nodes already agree is not a relay
 * scheme.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  compactNonce,
  fillMissing,
  reconstruct,
  savings,
  SHORT_ID_BYTES,
  shortId,
  toCompact,
} from '../src/net/compact.ts';
import { blockHash } from '../src/block.ts';
import { signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { fromHex, keyPairFromSeed } from '../src/crypto.ts';
import { pickUtxo, rig } from './helpers.ts';
import type { Block } from '../src/block.ts';
import type { Transaction } from '../src/tx.ts';

const DECKX = ZAPS_PER_DECKX;

/** A block containing `count` ordinary payments plus its coinbase. */
function blockWithPayments(count: number): { block: Block; payments: Transaction[] } {
  const { chain, miner } = rig('compact/miner');
  const payments: Transaction[] = [];

  let coin = pickUtxo(chain, miner.address);
  for (let i = 0; i < count; i++) {
    const payee = keyPairFromSeed(`compact/payee/${i}`);
    const send = 1n * DECKX;
    const tx = signTx(
      transferTx({
        inputs: [{ txid: coin.txid, vout: coin.vout }],
        outputs: [
          { value: send.toString(), address: payee.address },
          { value: (coin.value - send - 1000n).toString(), address: miner.address },
        ],
        memo: `payment ${i}`,
      }),
      miner,
      [{ value: coin.value, address: coin.address }],
    );
    payments.push(tx);
    // Chain the next payment onto this one's change output.
    coin = {
      txid: txid(tx),
      vout: 1,
      value: coin.value - send - 1000n,
      address: miner.address,
      height: chain.height,
      coinbase: false,
    };
  }

  const mined = chain.mineBlock(payments, miner.address, { time: chain.tip.header.time + 600 });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);
  return { block: mined.block, payments };
}

/* ────────────────────────────────────────────────────────── short ids ── */

test('short ids are six bytes and depend on the salt', () => {
  const key = fromHex('ab'.repeat(32));
  const other = fromHex('cd'.repeat(32));
  const id = 'ef'.repeat(32);

  const first = shortId(key, id);
  assert.equal(fromHex(first).length, SHORT_ID_BYTES);
  assert.equal(shortId(key, id), first, 'same key and id must agree');
  assert.notEqual(shortId(other, id), first, 'a different salt must give a different id');
});

test('every announcement uses a fresh salt', () => {
  const nonces = new Set(Array.from({ length: 50 }, () => compactNonce()));
  assert.equal(nonces.size, 50, 'nonces must not repeat');

  const { block } = blockWithPayments(3);
  const a = toCompact(block);
  const b = toCompact(block);
  assert.notEqual(a.nonce, b.nonce);
  assert.notDeepEqual(
    a.shortIds,
    b.shortIds,
    'two announcements of one block must not share short ids — that is the anti-collision defence',
  );
});

/* ─────────────────────────────────────────────────── reconstruction ── */

test('a peer holding every transaction rebuilds the block with no round trip', () => {
  const { block, payments } = blockWithPayments(5);
  const compact = toCompact(block);

  const result = reconstruct(compact, payments);

  assert.equal(result.ok, true, result.error);
  assert.deepEqual(result.missing, []);
  assert.equal(result.fromMempool, 5, 'all five came from the mempool');
  assert.equal(blockHash(result.block!.header), blockHash(block.header));
  assert.deepEqual(result.block!.transactions.map(txid), block.transactions.map(txid));
});

test('the coinbase is prefilled, because no mempool can hold it', () => {
  const { block } = blockWithPayments(3);
  const compact = toCompact(block);

  assert.equal(compact.prefilled.length, 1);
  assert.equal(compact.prefilled[0].index, 0);
  assert.equal(txid(compact.prefilled[0].transaction), txid(block.transactions[0]));
  assert.equal(compact.shortIds.length, block.transactions.length - 1);

  // With an empty mempool, only the coinbase is fillable — everything else is
  // reported missing rather than guessed at.
  const empty = reconstruct(compact, []);
  assert.equal(empty.ok, false);
  assert.deepEqual(empty.missing, [1, 2, 3]);
});

test('a peer missing some transactions asks for exactly those, then completes', () => {
  const { block, payments } = blockWithPayments(6);
  const compact = toCompact(block);

  // The peer has everything except the second and fifth payments.
  const partialPool = payments.filter((_, i) => i !== 1 && i !== 4);
  const first = reconstruct(compact, partialPool);

  assert.equal(first.ok, false);
  assert.deepEqual(first.missing, [2, 5], 'positions in the block, not in the pool');
  assert.equal(first.fromMempool, 4);

  // The sender supplies exactly those, in order.
  const supplied = [payments[1], payments[4]];
  const completed = fillMissing(compact, first, supplied, partialPool);

  assert.equal(completed.ok, true, completed.error);
  assert.equal(blockHash(completed.block!.header), blockHash(block.header));
  assert.deepEqual(completed.block!.transactions.map(txid), block.transactions.map(txid));
});

test('a peer sending the wrong number of transactions is refused', () => {
  const { block, payments } = blockWithPayments(4);
  const compact = toCompact(block);
  const partial = reconstruct(compact, payments.slice(0, 2));

  assert.equal(partial.missing.length, 2);
  const wrong = fillMissing(compact, partial, [payments[2]], payments.slice(0, 2));
  assert.equal(wrong.ok, false);
  assert.match(wrong.error!, /asked for 2 transactions, peer sent 1/);
});

test('unrelated transactions in the mempool do not confuse reconstruction', () => {
  const { block, payments } = blockWithPayments(4);
  const { payments: noise } = blockWithPayments(6);
  const compact = toCompact(block);

  // A realistic mempool: the block's transactions plus a lot that are not in it.
  const result = reconstruct(compact, [...noise, ...payments]);

  assert.equal(result.ok, true, result.error);
  assert.deepEqual(result.block!.transactions.map(txid), block.transactions.map(txid));
});

test('a malformed announcement is refused rather than throwing', () => {
  const { block, payments } = blockWithPayments(2);
  const compact = toCompact(block);

  assert.match(reconstruct({} as never, payments).error!, /malformed compact block/);
  assert.match(
    reconstruct({ ...compact, prefilled: [{ index: 99, transaction: block.transactions[0] }] }, payments).error!,
    /out of range/,
  );
  assert.match(
    reconstruct(
      { ...compact, prefilled: [compact.prefilled[0], compact.prefilled[0]] },
      payments,
    ).error!,
    /appears twice/,
  );
  assert.match(
    reconstruct({ ...compact, shortIds: [], prefilled: [] }, payments).error!,
    /announces no transactions/,
  );
  assert.match(
    reconstruct({ ...compact, shortIds: new Array(5000).fill('aa'.repeat(6)) }, payments).error!,
    /over the 4096 limit/,
  );
});

test('a reconstruction that slipped through is still caught by the chain', () => {
  /*
   * Six bytes is short enough that a collision is conceivable. The defence is
   * layered: the salt makes one impossible to arrange in advance, and if one
   * happens anyway the reconstructed block fails its Merkle commitment. This
   * simulates the second layer directly by substituting a transaction.
   */
  const { chain } = rig('compact/collision');
  const { block, payments } = blockWithPayments(3);
  const { payments: foreign } = blockWithPayments(1);

  const forged: Block = {
    header: block.header,
    transactions: [block.transactions[0], foreign[0], payments[1], payments[2]],
  };

  const res = chain.addBlock(forged, forged.header.time + 1);
  assert.equal(res.ok, false, 'a substituted transaction must not survive validation');
  assert.match(res.error!, /merkle root mismatch|prevHash|height/);
});

/* ────────────────────────────────────────────────────────── bandwidth ── */

test('a compact announcement is much smaller than the block', () => {
  const { block, payments } = blockWithPayments(40);
  const compact = toCompact(block);
  const size = savings(block, compact);

  assert.ok(
    size.ratio < 0.25,
    `expected a large saving, got ${(size.ratio * 100).toFixed(1)}% ` +
      `(${size.compactBytes} vs ${size.fullBytes} bytes)`,
  );

  // And it still reconstructs — a saving that loses information is not a saving.
  const rebuilt = reconstruct(compact, payments);
  assert.equal(rebuilt.ok, true, rebuilt.error);
  assert.equal(rebuilt.fromMempool, 40);
});

test('the saving grows with the number of transactions', () => {
  const small = blockWithPayments(2);
  const large = blockWithPayments(30);

  const smallRatio = savings(small.block, toCompact(small.block)).ratio;
  const largeRatio = savings(large.block, toCompact(large.block)).ratio;

  assert.ok(
    largeRatio < smallRatio,
    `a fuller block should compact better: ${largeRatio.toFixed(3)} vs ${smallRatio.toFixed(3)}`,
  );
});
