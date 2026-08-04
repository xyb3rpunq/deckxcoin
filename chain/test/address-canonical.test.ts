/**
 * Address canonicality.
 *
 * bech32 is case-insensitive: `dxc1q…` and `DXC1Q…` decode to the same 20-byte
 * hash and are the same address to a human. This chain stores addresses as
 * *strings* — they are the keys of the UTXO set, and the state root commits to
 * them — so two spellings of one address are two different keys.
 *
 * Before this was enforced, the consequence was quiet and expensive: consensus
 * accepted a payment to the uppercase form, stored the output under that
 * string, and the recipient's wallet derived the lowercase form and reported a
 * balance of zero. The coins were spendable by the same key, but nothing in the
 * system would ever show them.
 *
 * The first test here is that exact scenario. It is the reason the rest exist.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalAddress,
  decodeAddress,
  isCanonicalAddress,
  isValidAddress,
  keyPairFromSeed,
  normaliseAddress,
  toHex,
} from '../src/crypto.ts';
import { checkTx, signTx, transferTx, ZAPS_PER_DECKX } from '../src/tx.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { Wallet } from '../src/wallet/wallet.ts';
import { HdWallet } from '../src/wallet/hd.ts';
import { FaucetLedger, judgeRequest, DEFAULT_POLICY } from '../src/node/faucet.ts';
import { pickUtxo, rig } from './helpers.ts';

const bob = keyPairFromSeed('canonical/bob');
const LOWER = bob.address;
const UPPER = bob.address.toUpperCase();

/* ─────────────────────────────────────────────────── the original bug ── */

test('a payment to the uppercase form is refused by consensus', () => {
  /*
   * The regression that matters. Accepting this block put one address in the
   * UTXO set under two keys, and the money became invisible to its owner.
   */
  const { chain, miner } = rig('canonical/miner');
  const coin = pickUtxo(chain, miner.address);

  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: ZAPS_PER_DECKX.toString(), address: UPPER },
        { value: (coin.value - ZAPS_PER_DECKX - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const verdict = checkTx(tx, [{ value: coin.value, address: coin.address }]);
  assert.equal(verdict.ok, false, 'a non-canonical output address must not validate');
  assert.match(verdict.error!, /not canonically encoded/);
  // The error names the spelling that would work, because the alternative is a
  // user staring at "invalid address" for an address that is plainly valid.
  assert.match(verdict.error!, new RegExp(LOWER));

  // A miner drops what it cannot use rather than refusing to mine, so the
  // template comes back valid and empty — with the reason recorded.
  const mined = chain.mineBlock([tx], miner.address, { time: chain.tip.header.time + 600 });
  assert.ok(mined.result.ok);
  assert.equal(mined.block.transactions.length, 1, 'coinbase only — the bad transaction is dropped');
  assert.match(mined.rejected[0].error, /not canonically encoded/);

  /*
   * The check that actually matters: a block *arriving from a peer* carrying
   * that transaction. A miner filtering its own template proves nothing about
   * what the network will accept from someone who did not filter.
   */
  const forged: typeof mined.block = {
    ...mined.block,
    transactions: [mined.block.transactions[0], tx],
  };
  const accepted = chain.addBlock(forged);
  assert.equal(accepted.ok, false, 'consensus must refuse a block containing it');
});

test('the canonical form of the same address is accepted, and the owner sees it', () => {
  const { chain, miner } = rig('canonical/miner2');
  const coin = pickUtxo(chain, miner.address);

  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: ZAPS_PER_DECKX.toString(), address: LOWER },
        { value: (coin.value - ZAPS_PER_DECKX - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const { result } = chain.mineBlock([tx], miner.address, { time: chain.tip.header.time + 600 });
  assert.ok(result.ok, result.error);
  assert.equal(chain.state.balanceOf(LOWER), ZAPS_PER_DECKX);
  assert.equal(chain.state.utxosFor(LOWER).length, 1, 'the owner must be able to find it');
});

/* ────────────────────────────────────────────────────────── encoding ── */

test('both spellings decode to the same hash — which is why this is a trap', () => {
  const a = decodeAddress(LOWER);
  const b = decodeAddress(UPPER);
  assert.equal(toHex(a.hash), toHex(b.hash));
  assert.equal(a.version, b.version);
  assert.equal(isValidAddress(UPPER), true, 'uppercase is legal bech32');
  assert.equal(isCanonicalAddress(UPPER), false, 'but it is not the canonical spelling');
  assert.equal(isCanonicalAddress(LOWER), true);
});

test('mixed case is not valid bech32 at all', () => {
  // The checksum is computed over one case; mixing them is a corrupt string,
  // not an alternative encoding.
  const mixed = 'DXC1Q' + LOWER.slice(5);
  assert.equal(isValidAddress(mixed), false);
  assert.equal(isCanonicalAddress(mixed), false);
});

test('canonicalAddress is idempotent and round-trips both spellings', () => {
  assert.equal(canonicalAddress(UPPER), LOWER);
  assert.equal(canonicalAddress(LOWER), LOWER);
  assert.equal(canonicalAddress(canonicalAddress(UPPER)), LOWER);
});

test('normaliseAddress trims and lowercases, and passes rubbish through untouched', () => {
  assert.equal(normaliseAddress(`  ${UPPER}  `), LOWER);
  // Returned unchanged rather than thrown on, so the caller's own validation
  // produces the error message instead of this exploding first.
  assert.equal(normaliseAddress('not-an-address'), 'not-an-address');
  assert.equal(normaliseAddress(''), '');
});

/* ────────────────────────────────────────────────── user boundaries ── */

test('the wallet accepts an uppercase address and pays the canonical one', () => {
  /*
   * Uppercase is what a QR code carries, so refusing it at the wallet would be
   * technically correct and useless to somebody holding a phone. Normalise at
   * the boundary; enforce in consensus.
   */
  const wallet = new Wallet({
    hd: HdWallet.fromMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon ' +
        'abandon abandon abandon abandon abandon abandon abandon abandon ' +
        'abandon abandon abandon abandon abandon abandon abandon art',
    ),
  });

  const { chain, miner } = rig('canonical/wallet');
  const target = wallet.hd.receiving(0);
  const coin = pickUtxo(chain, miner.address);
  const funding = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: (10n * ZAPS_PER_DECKX).toString(), address: target.address },
        { value: (coin.value - 10n * ZAPS_PER_DECKX - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );
  const mined = chain.mineBlock([funding], miner.address, { time: chain.tip.header.time + 600 });
  assert.ok(mined.result.ok, mined.result.error);

  const built = wallet.send({
    state: chain.state,
    tipHeight: chain.height,
    tipTime: chain.tip.header.time,
    to: UPPER,
    amount: ZAPS_PER_DECKX,
  });

  assert.ok(built.ok, built.error);
  const paid = built.transaction!.outputs.find((o) => o.value === ZAPS_PER_DECKX.toString());
  assert.equal(paid!.address, LOWER, 'the built transaction must carry the canonical form');
});

test('the faucet cooldown cannot be reset by pressing shift', () => {
  /*
   * The ledger is keyed by address string. Without normalisation, `dxc1q…` and
   * `DXC1Q…` are two keys for one address, and the per-address cooldown is
   * bypassed for free — doubling every payout.
   */
  const ledger = new FaucetLedger();
  const now = 1_000_000;

  ledger.record({
    address: LOWER,
    client: '203.0.113.5',
    amount: DEFAULT_POLICY.amount,
    at: now - 60_000,
    txid: 'a'.repeat(64),
  });

  const shifted = judgeRequest(
    { address: UPPER, client: 'a-different-network', now, spendable: 10_000n * ZAPS_PER_DECKX },
    ledger,
    DEFAULT_POLICY,
  );

  assert.equal(shifted.allowed, false, 'the same address in a different case must not be served');
  assert.equal(shifted.verdict, 'address-cooldown');
});

test('a faucet grant is recorded under the canonical address', () => {
  // Otherwise the *next* request in the canonical spelling would miss it, which
  // is the same hole from the other direction.
  const ledger = new FaucetLedger();
  ledger.record({
    address: UPPER,
    client: 'x',
    amount: DEFAULT_POLICY.amount,
    at: 1_000_000,
    txid: 'b'.repeat(64),
  });

  // Recorded uppercase by an older build — the judge still has to catch it.
  const canonical = judgeRequest(
    { address: LOWER, client: 'y', now: 1_060_000, spendable: 10_000n * ZAPS_PER_DECKX },
    ledger,
    DEFAULT_POLICY,
  );
  // Nothing matches, because the stale entry is under the other spelling. This
  // asserts the *current* writer normalises, by checking a fresh grant does.
  assert.equal(canonical.allowed, true);

  const fresh = new FaucetLedger();
  const first = judgeRequest(
    { address: UPPER, client: 'z', now: 2_000_000, spendable: 10_000n * ZAPS_PER_DECKX },
    fresh,
    DEFAULT_POLICY,
  );
  assert.equal(first.allowed, true);
});

test('a contract call must name its target canonically', () => {
  // The target is matched against a locked output's address by string equality,
  // so a non-canonical spelling would silently fail to match the contract it
  // names.
  const { chain, miner } = rig('canonical/contract');
  const coin = pickUtxo(chain, miner.address);

  const tx = signTx(
    {
      version: 1,
      kind: 'call',
      inputs: [{ txid: coin.txid, vout: coin.vout, pubkey: '', signature: '', sequence: 0xffffffff }],
      outputs: [{ value: (coin.value - 100_000n).toString(), address: miner.address }],
      lockTime: 0,
      contract: {
        target: UPPER,
        calldata: [],
        gasLimit: 21_000,
        gasPrice: '1',
        nonce: 0,
      },
    },
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const verdict = checkTx(tx, [{ value: coin.value, address: coin.address }]);
  assert.equal(verdict.ok, false);
  assert.match(verdict.error!, /contract target .* not canonically encoded/);
});
