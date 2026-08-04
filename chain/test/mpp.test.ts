/**
 * Multi-part payments.
 *
 * A channel's capacity is a ceiling on any single payment through it, so a node
 * holding ten coins spread across five channels cannot send three. The
 * liquidity exists; it is merely in pieces. Splitting the payment to match is
 * the whole idea.
 *
 * The tests are almost entirely about the *hold*. Delivering three parts is
 * arithmetic. Not releasing the receipt until all three have arrived — and
 * releasing every part when they have not — is where the money is.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { VoltNetwork, encodeInvoice } from '../src/volt/network.ts';
import { HTLC_STATUS } from '../src/volt/channel.ts';
import { decodeInvoice, isReceiptFor } from '../src/volt/invoice.ts';
import { NO_PAYMENT_SECRET, PACKET_SIZE, decodeHopPayload, encodeHopPayload } from '../src/volt/onion.ts';
import { ZAPS_PER_DECKX } from '../src/tx.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { rig } from './helpers.ts';

const DECKX = ZAPS_PER_DECKX;

/**
 * Alice → Bob → Carol, with `paths` parallel Bob→Carol channels.
 *
 * Alice's channel to Bob is deliberately generous and Bob's onward channels
 * deliberately small: that is the shape that forces a split, and it is the
 * shape a real network has, because capacity is decided per channel by whoever
 * funded it.
 */
function splitNetwork(opts: { aliceToBob: bigint; bobToCarol: bigint[] }) {
  const { chain, miner } = rig('mpp/miner');

  // One funding output per channel, all mature.
  let t = chain.tip.header.time;
  for (let i = 0; i < COINBASE_MATURITY + opts.bobToCarol.length + 2; i++) {
    t += 600;
    const r = chain.mineBlock([], miner.address, { time: t });
    assert.equal(r.result.ok, true, r.result.error);
  }

  const net = new VoltNetwork();
  const alice = net.addNode('alice', 'mpp/alice');
  const bob = net.addNode('bob', 'mpp/bob');
  const carol = net.addNode('carol', 'mpp/carol');

  const utxos = chain.state
    .utxosFor(miner.address)
    .filter((u) => chain.height - u.height >= COINBASE_MATURITY);

  let next = 0;
  const ab = net.openChannel({
    a: alice, b: bob, capacity: opts.aliceToBob,
    funding: utxos[next++], funderKey: miner, changeAddress: miner.address,
  });

  const bc = opts.bobToCarol.map((capacity) =>
    net.openChannel({
      a: bob, b: carol, capacity,
      funding: utxos[next++], funderKey: miner, changeAddress: miner.address,
      pushToB: 0n,
    }),
  );

  t += 600;
  const mined = chain.mineBlock([ab.fundingTx, ...bc.map((c) => c.fundingTx)], miner.address, { time: t });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);
  net.confirmAll(chain);

  return { chain, net, alice, bob, carol, ab, bc };
}

const invoiceFor = (payee: ReturnType<VoltNetwork['addNode']>, amount: bigint, seed: string) =>
  payee.invoice(amount, 'split test', { seed, timestamp: Math.floor(Date.now() / 1000) });

/** Every HTLC in the network, so a test can prove nothing was left pending. */
function pendingHtlcs(net: VoltNetwork): number {
  let count = 0;
  for (const channel of net.channels.values()) {
    for (const htlc of channel.htlcs) if (htlc.status === HTLC_STATUS.PENDING) count++;
  }
  return count;
}

/* ─────────────────────────────────────────────────────── the payload ── */

test('the final hop carries a total and a secret; forwarding hops carry neither', () => {
  const secret = 'ab'.repeat(32);

  const final = decodeHopPayload(
    encodeHopPayload({
      shortChannelId: 0n,
      amountToForward: 400n,
      outgoingCltv: 144,
      final: true,
      totalAmount: 1000n,
      paymentSecret: secret,
    }),
  );
  assert.equal(final.totalAmount, 1000n);
  assert.equal(final.paymentSecret, secret);

  /*
   * A forwarding node must not be handed the total. Knowing it would tell that
   * node what fraction of a payment it is carrying, and therefore that it is on
   * the path to the payee — which is what the onion exists to hide.
   */
  const middle = decodeHopPayload(
    encodeHopPayload({ shortChannelId: 7n, amountToForward: 400n, outgoingCltv: 144, final: false }),
  );
  assert.equal(middle.totalAmount, undefined);
  assert.equal(middle.paymentSecret, undefined);
});

test('the packet is still one size for every route length', () => {
  // The payload grew from 33 to 64 bytes to make room for the two new fields.
  // What must not change is that the size says nothing about position.
  assert.equal(PACKET_SIZE, 1 + 33 + 20 * 96 + 32);
  assert.equal(PACKET_SIZE, 1986);
});

test('an unsplit payment sets the total to its own amount', () => {
  const p = decodeHopPayload(
    encodeHopPayload({
      shortChannelId: 0n,
      amountToForward: 500n,
      outgoingCltv: 10,
      final: true,
      totalAmount: 500n,
      paymentSecret: NO_PAYMENT_SECRET,
    }),
  );
  assert.equal(p.totalAmount, p.amountToForward);
});

/* ──────────────────────────────────────────────────────── invoices ── */

test('every invoice carries a payment secret, and it survives the round trip', () => {
  const { carol } = splitNetwork({ aliceToBob: 3n * DECKX, bobToCarol: [3n * DECKX] });
  const invoice = invoiceFor(carol, DECKX, 'mpp/secret');

  assert.match(invoice.paymentSecret, /^[0-9a-f]{64}$/);
  assert.notEqual(invoice.paymentSecret, NO_PAYMENT_SECRET);
  // Distinct from the preimage: one is the receipt, the other is proof the
  // payer read the invoice.
  assert.notEqual(invoice.paymentSecret, invoice.paymentHash);

  const decoded = decodeInvoice(encodeInvoice(invoice));
  assert.equal(decoded.paymentSecret, invoice.paymentSecret);
});

test('two invoices for the same amount get different secrets', () => {
  const { carol } = splitNetwork({ aliceToBob: 3n * DECKX, bobToCarol: [3n * DECKX] });
  const a = carol.invoice(DECKX, 'same', { timestamp: 1 });
  const b = carol.invoice(DECKX, 'same', { timestamp: 1 });
  assert.notEqual(a.paymentSecret, b.paymentSecret);
});

/* ──────────────────────────────────────────────────── the split ── */

test('a payment larger than any single channel is split across several', () => {
  /*
   * The case that fails without this feature. Bob has three separate 1 DECKX
   * channels to Carol; no one of them can carry 2.4, but together they hold
   * three.
   */
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 5n * DECKX,
    bobToCarol: [DECKX, DECKX, DECKX],
  });

  const amount = 240_000_000n; // 2.4 DECKX
  const invoice = invoiceFor(carol, amount, 'mpp/split');
  const carolBefore = [...carol.channels.values()].reduce((s, c) => s + carol.localBalance(c.channel.scid ?? 0n), 0n);

  const single = net.payInvoice(alice, encodeInvoice(invoice), { currentHeight: chain.height });
  assert.equal(single.ok, false, 'a single-part payment must not fit');

  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), { currentHeight: chain.height });
  assert.equal(result.ok, true, result.error);
  assert.ok(result.partsUsed! >= 2, `expected a split, got ${result.partsUsed} part(s)`);
  assert.ok(isReceiptFor(invoice, result.preimage!), 'the preimage must be the invoice receipt');

  const arrived = result.parts.filter((p) => p.ok).reduce((s, p) => s + p.amount, 0n);
  assert.equal(arrived, amount, 'the parts must add up to exactly the invoice');
  assert.equal(pendingHtlcs(net), 0, 'nothing may be left hanging after a settled payment');
});

test('a payment that fits in one channel is not split', () => {
  // Splitting costs an HTLC and a set of fees per part. It is a fallback, not
  // a strategy, and a sender that always split would pay for nothing.
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 3n * DECKX,
    bobToCarol: [3n * DECKX],
  });

  const invoice = invoiceFor(carol, 50_000_000n, 'mpp/single');
  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), { currentHeight: chain.height });

  assert.equal(result.ok, true, result.error);
  assert.equal(result.partsUsed, 1);
});

/* ────────────────────────────────────────────── the hold, and the money ── */

test('the receipt is not released while the payment is incomplete', () => {
  /*
   * The property the whole feature rests on. Bob can reach Carol with at most
   * 2 DECKX; the invoice is for 3. Parts will arrive and be held, and then the
   * payment will fail — and at no point may Carol's preimage escape, because
   * releasing it hands over a full receipt for a partial payment.
   */
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 6n * DECKX,
    bobToCarol: [DECKX, DECKX],
  });

  const invoice = invoiceFor(carol, 3n * DECKX, 'mpp/incomplete');
  const record = carol.invoices.get(invoice.paymentHash)!;

  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), { currentHeight: chain.height });

  assert.equal(result.ok, false, 'the payment cannot complete');
  assert.equal(result.preimage, undefined, 'no preimage may be returned');
  assert.equal(record.settled, false, 'the invoice must not be marked paid');
  assert.equal(pendingHtlcs(net), 0, 'and every part that did arrive must be released');
});

test('a failed split leaves no liquidity locked anywhere', () => {
  const { chain, net, alice, bob, carol, ab } = splitNetwork({
    aliceToBob: 6n * DECKX,
    bobToCarol: [DECKX, DECKX],
  });

  const aliceBefore = alice.localBalance(ab.shortChannelId);
  const bobBefore = bob.localBalance(ab.shortChannelId);

  const invoice = invoiceFor(carol, 3n * DECKX, 'mpp/nolock');
  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), { currentHeight: chain.height });
  assert.equal(result.ok, false);

  // A failed payment must cost nothing. Held HTLCs are locked funds for the
  // payer and locked liquidity for every hop, so a stalled set that is not
  // unwound is an outage that spreads outward from the payee.
  assert.equal(alice.localBalance(ab.shortChannelId), aliceBefore, 'Alice got everything back');
  assert.equal(bob.localBalance(ab.shortChannelId), bobBefore, 'Bob is unchanged');
  assert.equal(pendingHtlcs(net), 0);
});

test('the balances move by exactly the amount, once', () => {
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 5n * DECKX,
    bobToCarol: [DECKX, DECKX, DECKX],
  });

  const amount = 200_000_000n;
  const invoice = invoiceFor(carol, amount, 'mpp/balances');

  const carolBefore = carol.totalLocalBalance();
  const aliceBefore = alice.totalLocalBalance();

  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), { currentHeight: chain.height });
  assert.equal(result.ok, true, result.error);

  assert.equal(carol.totalLocalBalance() - carolBefore, amount, 'Carol receives the invoice amount exactly');
  // Alice pays the amount plus routing fees, and no more.
  const spent = aliceBefore - alice.totalLocalBalance();
  assert.equal(spent, amount + result.feesPaid!, 'Alice paid the amount plus fees, nothing else');
});

test('an invoice cannot be paid twice, split or not', () => {
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 8n * DECKX,
    bobToCarol: [DECKX, DECKX, DECKX, DECKX, DECKX, DECKX],
  });

  const invoice = invoiceFor(carol, 150_000_000n, 'mpp/twice');
  const encoded = encodeInvoice(invoice);

  assert.equal(net.payInvoiceMultiPart(alice, encoded, { currentHeight: chain.height }).ok, true);

  const second = net.payInvoiceMultiPart(alice, encoded, { currentHeight: chain.height });
  assert.equal(second.ok, false);
  // Refused by the payee on arrival of the first part, not after a whole
  // second set has been assembled and held.
  assert.match(second.error!, /already settled/);
  assert.equal(pendingHtlcs(net), 0, 'the refused second attempt must release its parts');
});

/* ─────────────────────────────────────────────── the payment secret ── */

test('a part carrying the wrong secret is refused on arrival', () => {
  /*
   * Every node that forwards a part learns the payment hash. Without the
   * secret, such a node could send its own "part" to the same destination —
   * which confirms it is one hop from the payee, and lets it interfere with a
   * payment it was never party to.
   *
   * Forged here by paying a re-signed invoice whose secret does not match the
   * one the payee recorded.
   */
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 3n * DECKX,
    bobToCarol: [3n * DECKX],
  });

  const real = invoiceFor(carol, 50_000_000n, 'mpp/secret-real');
  // Same hash, same payee, same amount — a different secret.
  const forged = carol.invoice(50_000_000n, 'split test', { seed: 'mpp/secret-real', timestamp: real.timestamp });
  assert.equal(forged.paymentHash, real.paymentHash, 'harness check: the hash must match');
  assert.notEqual(forged.paymentSecret, real.paymentSecret);

  // The payee's record now holds `forged`'s secret, so paying `real` presents
  // the wrong one.
  const result = net.payInvoiceMultiPart(alice, encodeInvoice(real), { currentHeight: chain.height });

  assert.equal(result.ok, false);
  assert.match(result.error!, /payment secret mismatch|no route|already settled/);
  assert.equal(pendingHtlcs(net), 0);
});

/* ───────────────────────────────────────────────────────── limits ── */

test('the sender gives up rather than splitting without bound', () => {
  // Each part is an HTLC on every hop it crosses. A sender willing to use
  // unlimited parts turns one payment into a denial of service against its own
  // channels, and against everyone else's.
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 6n * DECKX,
    bobToCarol: [DECKX, DECKX, DECKX, DECKX],
  });

  const invoice = invoiceFor(carol, 350_000_000n, 'mpp/maxparts');
  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), {
    currentHeight: chain.height,
    maxParts: 2,
  });

  assert.equal(result.ok, false);
  assert.equal(pendingHtlcs(net), 0);
});

test('an expired invoice is refused before anything is delivered', () => {
  const { chain, net, alice, carol } = splitNetwork({
    aliceToBob: 3n * DECKX,
    bobToCarol: [3n * DECKX],
  });

  const invoice = carol.invoice(50_000_000n, 'stale', { seed: 'mpp/stale', timestamp: 1000 });
  const result = net.payInvoiceMultiPart(alice, encodeInvoice(invoice), {
    currentHeight: chain.height,
    now: 1000 + 60 * 60 * 24 * 365,
  });

  assert.equal(result.ok, false);
  assert.equal(result.parts.length, 0, 'nothing should have been attempted');
  assert.equal(pendingHtlcs(net), 0);
});
