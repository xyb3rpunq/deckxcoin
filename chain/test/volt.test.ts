/**
 * Volt: channels on-chain and payments off-chain.
 *
 * The on-chain tests matter most. A channel is only as good as the
 * transactions it can fall back to, so every commitment, penalty and sweep
 * built here is fed to the real `Blockchain` validator — not asserted against
 * a mock.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { Blockchain } from '../src/chain.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { fromHex, keyPairFromSeed, sha256, toHex } from '../src/crypto.ts';
import {
  CHANNEL_STATE,
  DEFAULT_CSV_DELAY,
  HTLC_STATUS,
  VoltChannel,
} from '../src/volt/channel.ts';
import { VoltNetwork, fundingAddress, shortChannelId } from '../src/volt/network.ts';
import { checkInvoice, decodeInvoice, encodeInvoice, paymentSecretFromSeed } from '../src/volt/invoice.ts';
import { ChannelGraph, edgeFee } from '../src/volt/router.ts';
import { advance, pickUtxo, rig } from './helpers.ts';

const DECKX = ZAPS_PER_DECKX;

/** A confirmed two-party channel on a live regtest chain. */
function openPair(capacity = 2n * DECKX, pushToB = 0n) {
  const { chain, miner } = rig('volt/miner');
  const net = new VoltNetwork();
  const alice = net.addNode('alice', 'volt/alice');
  const bob = net.addNode('bob', 'volt/bob');

  // Give Alice on-chain coins from the miner.
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
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);

  net.confirmAll(chain);
  return { chain, miner, net, alice, bob, ...opened };
}

/* ------------------------------------------------------------- funding */

test('a channel is funded by a real 2-of-2 output on the chain', () => {
  const { chain, channel, fundingTx } = openPair();

  const utxo = chain.state.getUtxo(txid(fundingTx), 0);
  assert.ok(utxo, 'funding output must be in the UTXO set');
  assert.equal(utxo!.value, channel.capacity);
  assert.equal(utxo!.script?.type, 'multisig2');
  assert.equal(utxo!.address, fundingAddress(
    toHex(channel.a.key.publicKey),
    toHex(channel.b.key.publicKey),
  ));
  assert.equal(channel.state, CHANNEL_STATE.OPEN);
});

test('short channel id is derived from the funding outpoint', () => {
  const { fundingTx, shortChannelId: scid } = openPair();
  assert.equal(scid, shortChannelId(txid(fundingTx), 0));
});

/* ----------------------------------------------------------- payments */

test('off-chain payments move balance and revoke the previous state', () => {
  const { channel } = openPair(2n * DECKX);
  const start = channel.commitmentNumber;

  channel.pay('a', 30_000_000n);
  channel.pay('a', 20_000_000n);
  channel.pay('b', 5_000_000n);

  assert.equal(channel.balanceA, 2n * DECKX - 45_000_000n);
  assert.equal(channel.balanceB, 45_000_000n);
  assert.equal(channel.balanceA + channel.balanceB, channel.capacity);
  assert.equal(channel.commitmentNumber, start + 3);
  assert.equal(channel.revokedByA.size, 3, 'every superseded state must be revoked');
});

test('a payment larger than the spendable balance is refused', () => {
  const { channel } = openPair(1n * DECKX);
  assert.throws(() => channel.pay('b', 1n), /insufficient spendable/);
  assert.throws(() => channel.pay('a', 2n * DECKX), /insufficient spendable/);
});

/* ------------------------------------------------------- cooperative close */

test('cooperative close settles on-chain with the final balances', () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  channel.pay('a', 60_000_000n);

  const fee = 1000n;
  const closeTx = channel.cooperativeClose(fee);
  const t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([closeTx], miner.address, { time: t });

  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);
  assert.equal(chain.state.balanceOf(channel.a.key.address), channel.balanceA - fee);
  assert.equal(chain.state.balanceOf(channel.b.key.address), channel.balanceB);
  assert.equal(chain.auditSupply().balanced, true);
});

test('a cooperative close needs both signatures — one is not enough', () => {
  const { chain, channel } = openPair();
  const closeTx = channel.cooperativeClose();
  const stripped = {
    ...closeTx,
    inputs: closeTx.inputs.map((i) => ({ ...i, cosign: undefined })),
  };
  const res = chain.applyTransaction(stripped, chain.state.clone(), {
    height: chain.height + 1,
    time: chain.tip.header.time + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /cosignature/);
});

/* -------------------------------------------------------------- force close */

test('force close broadcasts the latest commitment, and it validates on-chain', () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  channel.pay('a', 50_000_000n);

  const commitment = channel.forceClose('a');
  const t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([commitment], miner.address, { time: t });

  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);

  // Alice's own output is timelocked; Bob's is immediately spendable.
  const local = commitment.outputs.find((o) => o.script?.type === 'revocable');
  assert.ok(local, 'commitment must carry a revocable to_local output');
  assert.equal((local!.script as { delay: number }).delay, DEFAULT_CSV_DELAY);
  assert.equal(BigInt(local!.value), channel.balanceA);

  const remote = commitment.outputs.find((o) => !o.script);
  assert.equal(BigInt(remote!.value), channel.balanceB);
});

test("the broadcaster cannot sweep its own output before the CSV delay", () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  channel.pay('a', 50_000_000n);
  const commitment = channel.forceClose('a');

  let t = chain.tip.header.time + 600;
  chain.mineBlock([commitment], miner.address, { time: t });

  const idx = commitment.outputs.findIndex((o) => o.script?.type === 'revocable');
  const value = BigInt(commitment.outputs[idx].value);

  // Sequence below the required delay: rejected by the script rule.
  let early = transferTx({
    inputs: [{ txid: txid(commitment), vout: idx, sequence: 10 }],
    outputs: [{ value: (value - 1000n).toString(), address: channel.a.key.address }],
  });
  early = signTx(early, channel.a.key, [
    { value, address: commitment.outputs[idx].address, script: commitment.outputs[idx].script },
  ]);

  const res = chain.applyTransaction(early, chain.state.clone(), {
    height: chain.height + 1,
    time: t + 600,
  });
  assert.equal(res.ok, false);
  assert.match(res.error!, /sequence >=/);
});

/* ---------------------------------------------------------------- penalty */

test('PENALTY: broadcasting a revoked commitment loses the cheater everything', () => {
  // Push some balance to Bob at open, so the stale commitment carries a
  // to_remote output too — an all-dust commitment would not exercise the
  // full sweep.
  const { chain, miner, channel } = openPair(2n * DECKX, 50_000_000n);

  const revokedNumber = channel.commitmentNumber;
  const staleCommitment = channel.history[revokedNumber].forA;

  // Alice pays Bob repeatedly, so the stale state — where she held more —
  // becomes strictly better for her than the current one.
  channel.pay('a', 100_000_000n);
  channel.pay('a', 10_000_000n);
  channel.pay('b', 1_000_000n);

  // Alice cheats: she broadcasts the old commitment, where she held more.
  let t = chain.tip.header.time + 600;
  const cheat = chain.mineBlock([staleCommitment], miner.address, { time: t });
  assert.deepEqual(cheat.rejected, []);
  assert.equal(cheat.result.ok, true, cheat.result.error);

  const staleAliceOut = staleCommitment.outputs.find((o) => o.script?.type === 'revocable');
  const staleBobOut = staleCommitment.outputs.find((o) => !o.script);
  const swept = BigInt(staleAliceOut!.value) + BigInt(staleBobOut!.value);

  // Bob punishes her. No CSV wait — the revocation branch is immediate.
  const penaltyFee = 1000n;
  const penalty = channel.penaltyFor(
    staleCommitment,
    revokedNumber,
    'a',
    channel.b.key.address,
    penaltyFee,
  );

  t += 600;
  const punished = chain.mineBlock([penalty], miner.address, { time: t });
  assert.deepEqual(punished.rejected, []);
  assert.equal(punished.result.ok, true, punished.result.error);

  assert.equal(chain.state.balanceOf(channel.b.key.address), swept - penaltyFee);
  assert.equal(chain.state.balanceOf(channel.a.key.address), 0n, 'the cheater keeps nothing');
  assert.equal(chain.auditSupply().balanced, true);
});

test('the cheater cannot forge the revocation key for its own commitment', () => {
  const { channel } = openPair();
  channel.pay('a', 1_000_000n);
  const stale = channel.history[0].forA;
  const revocable = stale.outputs.find((o) => o.script?.type === 'revocable');
  const revKey = (revocable!.script as { revocationKey: string }).revocationKey;

  // The revocation key is not either party's node key, and not derivable from
  // Alice's per-commitment secret alone.
  assert.notEqual(revKey, toHex(channel.a.key.publicKey));
  assert.notEqual(revKey, toHex(channel.b.key.publicKey));
  assert.notEqual(revKey, channel.a.secrets.point(0));
});

/* ------------------------------------------------------------------ HTLC */

test('an HTLC suspends value until the preimage appears', () => {
  const { channel } = openPair(2n * DECKX);
  const { preimage, paymentHash } = paymentSecretFromSeed('htlc/one');

  const before = channel.balanceA;
  const htlc = channel.addHtlc('a', 25_000_000n, paymentHash, 500);

  assert.equal(channel.balanceA, before, 'balance does not move on offer');
  assert.equal(channel.spendable('a'), before - 25_000_000n, 'but it is no longer spendable');

  channel.settleHtlc(htlc.id, preimage);
  assert.equal(channel.balanceA, before - 25_000_000n);
  assert.equal(channel.balanceB, 25_000_000n);
  assert.equal(htlc.status, HTLC_STATUS.SETTLED);
});

test('a wrong preimage cannot settle an HTLC', () => {
  const { channel } = openPair();
  const { paymentHash } = paymentSecretFromSeed('htlc/two');
  const htlc = channel.addHtlc('a', 1_000_000n, paymentHash, 500);
  const wrong = toHex(sha256(fromHex('00'.repeat(32))));
  assert.throws(() => channel.settleHtlc(htlc.id, wrong), /does not match/);
});

test('a failed HTLC returns the value to the offerer', () => {
  const { channel } = openPair();
  const { paymentHash } = paymentSecretFromSeed('htlc/three');
  const before = channel.balanceA;
  const htlc = channel.addHtlc('a', 1_000_000n, paymentHash, 500);
  channel.failHtlc(htlc.id);
  assert.equal(channel.balanceA, before);
  assert.equal(channel.spendable('a'), before);
});

test('ON-CHAIN: an HTLC output is swept by revealing the preimage', () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  const { preimage, paymentHash } = paymentSecretFromSeed('htlc/onchain');
  channel.addHtlc('a', 40_000_000n, paymentHash, chain.height + 200);

  const commitment = channel.forceClose('a');
  let t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([commitment], miner.address, { time: t });
  assert.equal(mined.result.ok, true, mined.result.error);

  const idx = commitment.outputs.findIndex((o) => o.script?.type === 'htlc');
  assert.ok(idx >= 0, 'commitment must carry the HTLC output');

  const sweep = channel.sweepHtlcWithPreimage(commitment, idx, preimage, 'b');
  t += 600;
  const claimed = chain.mineBlock([sweep], miner.address, { time: t });
  assert.deepEqual(claimed.rejected, []);
  assert.equal(claimed.result.ok, true, claimed.result.error);
  assert.equal(chain.state.balanceOf(channel.b.key.address), 40_000_000n - 500n);
});

test('ON-CHAIN: an HTLC without the preimage cannot be swept by the payee', () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  const { paymentHash } = paymentSecretFromSeed('htlc/nopreimage');
  channel.addHtlc('a', 40_000_000n, paymentHash, chain.height + 200);

  const commitment = channel.forceClose('a');
  const t = chain.tip.header.time + 600;
  chain.mineBlock([commitment], miner.address, { time: t });

  const idx = commitment.outputs.findIndex((o) => o.script?.type === 'htlc');
  const wrong = toHex(new Uint8Array(32));
  assert.throws(
    () => {
      const tx = channel.sweepHtlcWithPreimage(commitment, idx, wrong, 'b');
      const res = chain.applyTransaction(tx, chain.state.clone(), {
        height: chain.height + 1,
        time: t + 600,
      });
      if (!res.ok) throw new Error(res.error);
    },
    /preimage does not hash|refund key/,
  );
});

test('ON-CHAIN: the payer reclaims an expired HTLC after its timeout', () => {
  const { chain, miner, channel } = openPair(2n * DECKX);
  const { paymentHash } = paymentSecretFromSeed('htlc/timeout');
  const timeout = chain.height + 5;
  channel.addHtlc('a', 40_000_000n, paymentHash, timeout);

  const commitment = channel.forceClose('a');
  let t = chain.tip.header.time + 600;
  chain.mineBlock([commitment], miner.address, { time: t });

  const idx = commitment.outputs.findIndex((o) => o.script?.type === 'htlc');

  // Too early: the chain's absolute-locktime rule blocks it.
  const early = channel.refundHtlc(commitment, idx, 'a', timeout);
  const rejected = chain.applyTransaction(early, chain.state.clone(), {
    height: chain.height + 1,
    time: t + 600,
  });
  assert.equal(rejected.ok, false);
  assert.match(rejected.error!, /locktime not met/);

  // After the timeout height, the refund confirms.
  advance(chain, miner.address, 6);
  const refund = channel.refundHtlc(commitment, idx, 'a', timeout);
  t = chain.tip.header.time + 600;
  const ok = chain.mineBlock([refund], miner.address, { time: t });
  assert.deepEqual(ok.rejected, []);
  assert.equal(ok.result.ok, true, ok.result.error);

  // Assert on the refund output itself. Alice's total balance also contains
  // her to_local output from the same commitment, which is a different claim.
  const refunded = chain.state.getUtxo(txid(refund), 0);
  assert.ok(refunded, 'refund output must exist');
  assert.equal(refunded!.value, 40_000_000n - 500n);
  assert.equal(refunded!.address, channel.a.key.address);
});

/* --------------------------------------------------------------- invoices */

test('invoices round-trip through bech32m and verify', () => {
  const { alice } = openPair();
  const inv = alice.invoice(12_345_678n, 'coffee at the REKT bar', { seed: 'inv/1', timestamp: 1_785_628_800 });
  const encoded = encodeInvoice(inv);

  assert.match(encoded, /^lnvolt1/);
  const decoded = decodeInvoice(encoded);
  assert.deepEqual(decoded, inv);

  const check = checkInvoice(decoded, 1_785_628_900);
  assert.equal(check.ok, true, check.error);
});

test('a tampered invoice fails signature verification', () => {
  const { alice } = openPair();
  const inv = alice.invoice(1000n, 'x', { seed: 'inv/2', timestamp: 1_785_628_800 });
  const forged = { ...inv, amount: 999_999_999n };
  const check = checkInvoice(forged, 1_785_628_900);
  assert.equal(check.ok, false);
  assert.match(check.error!, /signature/);
});

test('an expired invoice is refused', () => {
  const { alice } = openPair();
  const inv = alice.invoice(1000n, 'x', { seed: 'inv/3', timestamp: 1_785_628_800 });
  const check = checkInvoice(inv, 1_785_628_800 + 7200);
  assert.equal(check.ok, false);
  assert.match(check.error!, /expired/);
});

/* ---------------------------------------------------------------- routing */

test('the router charges base + proportional fees and accumulates CLTV', () => {
  const graph = new ChannelGraph();
  const [a, b, c] = ['aa', 'bb', 'cc'].map((s) => s.repeat(33));
  graph.addBidirectional(1n, a, b, 10n * DECKX, { baseFee: 1000n, feeRatePpm: 500n, cltvDelta: 40 });
  graph.addBidirectional(2n, b, c, 10n * DECKX, { baseFee: 2000n, feeRatePpm: 1000n, cltvDelta: 80 });

  const route = graph.findRoute({
    source: a,
    destination: c,
    amount: 1_000_000n,
    finalCltvDelta: 18,
    currentHeight: 100,
  });

  assert.ok(route, 'a two-hop route must exist');
  assert.equal(route!.hops.length, 2);
  // Only the middle hop charges; the sender's own channel is free.
  const expectedFee = 2000n + (1_000_000n * 1000n) / 1_000_000n;
  assert.equal(route!.totalFees, expectedFee);
  assert.equal(route!.totalAmount, 1_000_000n + expectedFee);
  // 100 + 18 (final) + 80 (c's incoming delta) = 198
  assert.equal(route!.totalCltv, 198);
});

test('the router prefers the cheaper of two parallel paths', () => {
  const graph = new ChannelGraph();
  const [a, b, c, d] = ['aa', 'bb', 'cc', 'dd'].map((s) => s.repeat(33));
  graph.addBidirectional(1n, a, b, 10n * DECKX, { baseFee: 1n, feeRatePpm: 10n });
  graph.addBidirectional(2n, b, d, 10n * DECKX, { baseFee: 1n, feeRatePpm: 10n });
  graph.addBidirectional(3n, a, c, 10n * DECKX, { baseFee: 100_000n, feeRatePpm: 5000n });
  graph.addBidirectional(4n, c, d, 10n * DECKX, { baseFee: 100_000n, feeRatePpm: 5000n });

  const route = graph.findRoute({
    source: a,
    destination: d,
    amount: 1_000_000n,
    finalCltvDelta: 18,
    currentHeight: 0,
  });
  assert.ok(route);
  assert.deepEqual(route!.hops.map((h) => h.shortChannelId), [1n, 2n]);
});

test('a route wider than any channel capacity is not returned', () => {
  const graph = new ChannelGraph();
  const [a, b] = ['aa', 'bb'].map((s) => s.repeat(33));
  graph.addBidirectional(1n, a, b, 1000n);
  const route = graph.findRoute({
    source: a,
    destination: b,
    amount: 10_000n,
    finalCltvDelta: 18,
    currentHeight: 0,
  });
  assert.equal(route, undefined);
});

test('edgeFee matches the published policy', () => {
  const edge = {
    shortChannelId: 1n,
    from: 'a',
    to: 'b',
    capacity: DECKX,
    baseFee: 1000n,
    feeRatePpm: 2500n,
    cltvDelta: 40,
    maxHtlc: DECKX,
    minHtlc: 1n,
  };
  assert.equal(edgeFee(edge, 1_000_000n), 1000n + 2500n);
});

/* ------------------------------------------------------ end-to-end routing */

/** Alice → Bob → Carol, each channel funded and confirmed on the chain. */
function threeNodeNetwork() {
  const chain = Blockchain.regtest();
  const miner = keyPairFromSeed('deckxcoin/regtest');

  let t = chain.tip.header.time;
  for (let i = 0; i <= COINBASE_MATURITY + 2; i++) {
    t += 600;
    const r = chain.mineBlock([], miner.address, { time: t });
    assert.equal(r.result.ok, true, r.result.error);
  }

  const net = new VoltNetwork();
  const alice = net.addNode('alice', 'e2e/alice');
  const bob = net.addNode('bob', 'e2e/bob');
  const carol = net.addNode('carol', 'e2e/carol');

  const utxos = chain.state
    .utxosFor(miner.address)
    .filter((u) => chain.height - u.height >= COINBASE_MATURITY);

  const ab = net.openChannel({
    a: alice, b: bob, capacity: 3n * DECKX,
    funding: utxos[0], funderKey: miner, changeAddress: miner.address,
  });
  const bc = net.openChannel({
    a: bob, b: carol, capacity: 3n * DECKX,
    funding: utxos[1], funderKey: miner, changeAddress: miner.address,
    pushToB: 0n,
  });

  t += 600;
  const mined = chain.mineBlock([ab.fundingTx, bc.fundingTx], miner.address, { time: t });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);

  net.confirmAll(chain);
  return { chain, miner, net, alice, bob, carol, ab, bc };
}

test('END TO END: Alice pays Carol through Bob, atomically', () => {
  const { chain, net, alice, bob, carol, ab, bc } = threeNodeNetwork();

  // Bob needs outbound liquidity towards Carol, so he must hold balance in
  // the B→C channel. He is side 'a' there, and starts with the full capacity.
  assert.ok(bob.localBalance(bc.shortChannelId) > 0n);

  const amount = 50_000_000n;
  const invoice = carol.invoice(amount, 'REKT hoodie', {
    seed: 'e2e/invoice',
    timestamp: Math.floor(Date.now() / 1000),
  });

  const aliceBefore = alice.localBalance(ab.shortChannelId);
  const carolBefore = carol.localBalance(bc.shortChannelId);
  const bobAB = bob.localBalance(ab.shortChannelId);
  const bobBC = bob.localBalance(bc.shortChannelId);

  const result = net.payInvoice(alice, encodeInvoice(invoice), { currentHeight: chain.height });
  assert.equal(result.ok, true, result.error);
  assert.equal(result.route!.hops.length, 2);
  assert.equal(result.forwards.length, 2);
  assert.equal(result.forwards[0].node, 'bob');
  assert.equal(result.forwards[1].node, 'carol');

  // Carol received exactly the invoice amount.
  assert.equal(carol.localBalance(bc.shortChannelId), carolBefore + amount);
  // Alice paid the amount plus routing fees.
  assert.equal(alice.localBalance(ab.shortChannelId), aliceBefore - result.amountSent!);
  // Bob is up by exactly his fee: he received more than he forwarded.
  const bobDelta =
    bob.localBalance(ab.shortChannelId) - bobAB + (bob.localBalance(bc.shortChannelId) - bobBC);
  assert.equal(bobDelta, result.feesPaid!);
  assert.ok(result.feesPaid! > 0n, 'the routing hop must be paid');

  // Preimage is a valid receipt.
  assert.equal(toHex(sha256(fromHex(result.preimage!))), invoice.paymentHash);

  // No HTLC left hanging anywhere.
  for (const channel of net.channels.values()) {
    assert.equal(channel.htlcs.filter((h) => h.status === HTLC_STATUS.PENDING).length, 0);
    assert.equal(channel.balanceA + channel.balanceB, channel.capacity);
  }
  void ab;
});

test('END TO END: a payment that cannot complete leaves every balance untouched', () => {
  const { chain, net, alice, carol, ab, bc } = threeNodeNetwork();

  const before = {
    a: alice.localBalance(ab.shortChannelId),
    c: carol.localBalance(bc.shortChannelId),
  };

  // More than the B→C channel can carry.
  const invoice = carol.invoice(5n * DECKX, 'too big', {
    seed: 'e2e/toobig',
    timestamp: Math.floor(Date.now() / 1000),
  });
  const result = net.payInvoice(alice, encodeInvoice(invoice), { currentHeight: chain.height });

  assert.equal(result.ok, false);
  assert.equal(alice.localBalance(ab.shortChannelId), before.a);
  assert.equal(carol.localBalance(bc.shortChannelId), before.c);
  for (const channel of net.channels.values()) {
    assert.equal(channel.htlcs.filter((h) => h.status === HTLC_STATUS.PENDING).length, 0);
  }
});

test('END TO END: paying the same invoice twice fails the second time', () => {
  const { chain, net, alice, carol } = threeNodeNetwork();
  const invoice = carol.invoice(10_000_000n, 'once only', {
    seed: 'e2e/once',
    timestamp: Math.floor(Date.now() / 1000),
  });
  const encoded = encodeInvoice(invoice);

  const first = net.payInvoice(alice, encoded, { currentHeight: chain.height });
  assert.equal(first.ok, true, first.error);

  const second = net.payInvoice(alice, encoded, { currentHeight: chain.height });
  assert.equal(second.ok, false);
  assert.match(second.error!, /already settled/);
});

test('the network reports consistent aggregate statistics', () => {
  const { net } = threeNodeNetwork();
  const stats = net.stats();
  assert.equal(stats.nodes, 3);
  assert.equal(stats.channels, 2);
  assert.equal(stats.openChannels, 2);
  assert.equal(BigInt(stats.capacity), 6n * DECKX);
  assert.equal(net.graph.nodeCount, 3);
  assert.equal(net.graph.channelCount, 2);
});

test('a channel object refuses balances that do not sum to capacity', () => {
  assert.throws(
    () =>
      new VoltChannel({
        id: 'bad',
        a: { name: 'a' } as never,
        b: { name: 'b' } as never,
        funding: { txid: '00'.repeat(32), vout: 0, value: 100n, address: 'x', script: { type: 'p2pkh' } },
        balanceA: 60n,
        balanceB: 60n,
      }),
    /must sum to funding value/,
  );
});

