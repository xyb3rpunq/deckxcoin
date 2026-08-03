/**
 * The wallet.
 *
 * A wallet is where a protocol meets a person, and the failure modes are
 * different from consensus failures: nobody loses money because a wallet
 * computed a Merkle root wrongly, they lose it because the change output went
 * somewhere they do not control, or because a mistyped seed word silently
 * opened a different wallet.
 *
 * The tests are weighted accordingly. Every transaction the wallet builds is
 * run through the chain's own validator, and the recovery tests actually throw
 * the wallet away and rebuild it from the words.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  completeWord,
  derivationPath,
  GAP_LIMIT,
  generateMnemonic,
  HdWallet,
  isWord,
  normaliseMnemonic,
  validateMnemonic,
} from '../src/wallet/hd.ts';
import {
  COIN_STRATEGY,
  DUST_THRESHOLD,
  estimateSize,
  Wallet,
} from '../src/wallet/wallet.ts';
import { formatDeckx, signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { isValidAddress, toHex } from '../src/crypto.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { advance, pickUtxo, rig } from './helpers.ts';
import type { Blockchain } from '../src/chain.ts';

const DECKX = ZAPS_PER_DECKX;

/** A known-good mnemonic, so tests are reproducible. */
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

function walletFrom(mnemonic = TEST_MNEMONIC, passphrase = ''): Wallet {
  return new Wallet({ hd: HdWallet.fromMnemonic(mnemonic, passphrase) });
}

/** A regtest chain with `amount` paid to the wallet's first receiving address. */
function fundedChain(wallet: Wallet, amount = 10n * DECKX) {
  const { chain, miner } = rig('wallet/miner');
  const target = wallet.hd.receiving(0);

  const coin = pickUtxo(chain, miner.address);
  const funding = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: amount.toString(), address: target.address },
        { value: (coin.value - amount - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const t = chain.tip.header.time + 600;
  const mined = chain.mineBlock([funding], miner.address, { time: t });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);
  return { chain, miner, target };
}

const view = (chain: Blockchain) => ({
  state: chain.state,
  tipHeight: chain.height,
  tipTime: chain.tip.header.time,
});

/* ────────────────────────────────────────────────────────── mnemonics ── */

test('a generated mnemonic is 24 words and validates', () => {
  const mnemonic = generateMnemonic();
  assert.equal(mnemonic.split(' ').length, 24);
  assert.equal(validateMnemonic(mnemonic), true);
  for (const word of mnemonic.split(' ')) assert.equal(isWord(word), true);
});

test('12-word mnemonics are supported too', () => {
  const mnemonic = generateMnemonic(128);
  assert.equal(mnemonic.split(' ').length, 12);
  assert.equal(validateMnemonic(mnemonic), true);
});

test('two generated mnemonics are never the same', () => {
  const seen = new Set(Array.from({ length: 25 }, () => generateMnemonic()));
  assert.equal(seen.size, 25, 'entropy source is not producing distinct mnemonics');
});

test('the checksum catches a single wrong word', () => {
  assert.equal(validateMnemonic(TEST_MNEMONIC), true);

  // Swap the last word for another valid word. Without a checksum this would
  // silently open a different wallet.
  const wrong = TEST_MNEMONIC.replace(/art$/, 'zoo');
  assert.equal(validateMnemonic(wrong), false);
  assert.throws(() => HdWallet.fromMnemonic(wrong), /checksum did not match/);

  // A word that is not in the list at all.
  assert.equal(validateMnemonic(TEST_MNEMONIC.replace(/art$/, 'notaword')), false);
  // The right words in the wrong order.
  const words = TEST_MNEMONIC.split(' ');
  const swapped = [...words.slice(0, 22), words[23], words[22]].join(' ');
  assert.equal(validateMnemonic(swapped), false);
});

test('mnemonics are normalised before use, so paste quirks do not matter', () => {
  const messy = `  ${TEST_MNEMONIC.toUpperCase().replace(/ /g, '\n  ')}  `;
  assert.equal(normaliseMnemonic(messy), TEST_MNEMONIC);
  assert.equal(validateMnemonic(messy), true);
  assert.equal(
    HdWallet.fromMnemonic(messy).receiving(0).address,
    HdWallet.fromMnemonic(TEST_MNEMONIC).receiving(0).address,
  );
});

test('truncating every word to four letters still identifies it uniquely', () => {
  /*
   * BIP-39's actual guarantee, stated precisely: truncating all 2048 words to
   * their first four letters yields 2048 distinct strings. That is what makes
   * a smudged or truncated backup recoverable.
   *
   * It is *not* the stronger claim that a four-letter prefix matches exactly
   * one word — "art" is a complete word and also a prefix of "artefact",
   * "artist" and "artwork". A recovery tool must compare truncations, not
   * prefixes, and getting that backwards would make it reject valid backups.
   */
  const truncations = new Set<string>();
  let words = 0;
  for (let i = 0; i < 2048; i++) {
    // Walk the list through the completion helper rather than importing it.
    const matches = completeWord(String.fromCharCode(97 + (i % 26)));
    for (const word of matches) {
      truncations.add(word.slice(0, 4));
      words++;
    }
    if (i >= 25) break;
  }
  assert.equal(truncations.size, words, 'no two words may share a four-letter truncation');
  assert.ok(words > 2000, `expected the whole wordlist, walked ${words}`);

  // The completion helper does prefix matching, which is the right behaviour
  // for a "type the first letters" interface — and returns several for a short
  // word that is also a prefix.
  assert.deepEqual(completeWord('abandon'), ['abandon']);
  assert.ok(completeWord('art').length > 1, "'art' is a word and a prefix of others");
  assert.ok(completeWord('aban').length >= 1);
});

/* ────────────────────────────────────────────────────────── derivation ── */

test('derivation is deterministic and follows the documented path', () => {
  const a = HdWallet.fromMnemonic(TEST_MNEMONIC);
  const b = HdWallet.fromMnemonic(TEST_MNEMONIC);

  const key = a.receiving(0);
  assert.equal(key.address, b.receiving(0).address);
  assert.equal(key.path, "m/84'/9333'/0'/0/0");
  assert.equal(key.path, derivationPath(0, 0, 0));
  assert.equal(isValidAddress(key.address), true);
  assert.equal(key.publicKey.length, 32, 'wallet keys are x-only, like every other key here');
});

test('every derived address is distinct', () => {
  const hd = HdWallet.fromMnemonic(TEST_MNEMONIC);
  const addresses = new Set<string>();
  for (let i = 0; i < 50; i++) {
    addresses.add(hd.receiving(i).address);
    addresses.add(hd.change(i).address);
  }
  assert.equal(addresses.size, 100, 'derived addresses must never collide');
});

test('receive and change branches never overlap', () => {
  const hd = HdWallet.fromMnemonic(TEST_MNEMONIC);
  const receive = new Set(Array.from({ length: 40 }, (_, i) => hd.receiving(i).address));
  for (let i = 0; i < 40; i++) {
    assert.equal(receive.has(hd.change(i).address), false, 'a change address leaked into receive');
  }
});

test('a passphrase produces a different wallet, indistinguishably', () => {
  const plain = HdWallet.fromMnemonic(TEST_MNEMONIC);
  const guarded = HdWallet.fromMnemonic(TEST_MNEMONIC, 'correct horse battery staple');
  const wrong = HdWallet.fromMnemonic(TEST_MNEMONIC, 'correct horse battery stapl');

  assert.notEqual(plain.receiving(0).address, guarded.receiving(0).address);
  // A wrong passphrase is not an error — it is simply another wallet. That is
  // the deniability property, and it is also why forgetting it is fatal.
  assert.notEqual(guarded.receiving(0).address, wrong.receiving(0).address);
  assert.equal(isValidAddress(wrong.receiving(0).address), true);
});

test('accounts are separated', () => {
  const first = HdWallet.fromMnemonic(TEST_MNEMONIC, '', 0);
  const second = HdWallet.fromMnemonic(TEST_MNEMONIC, '', 1);
  assert.notEqual(first.receiving(0).address, second.receiving(0).address);
  assert.equal(second.receiving(0).path, "m/84'/9333'/1'/0/0");
});

test('the account xpub identifies the wallet without revealing it', () => {
  const hd = HdWallet.fromMnemonic(TEST_MNEMONIC);
  const xpub = hd.accountXpub();
  assert.match(xpub, /^xpub/);
  assert.equal(xpub.includes(toHex(hd.receiving(0).privateKey)), false, 'an xpub must never carry a secret');
  assert.equal(hd.fingerprint().length, 8);
});

/* ────────────────────────────────────────────────────────── balances ── */

test('the wallet finds coins paid to a derived address', () => {
  const wallet = walletFrom();
  const { chain, target } = fundedChain(wallet, 7n * DECKX);

  const balance = wallet.balance(chain.state, chain.height);
  assert.equal(balance.total, 7n * DECKX);
  assert.equal(balance.spendable, 7n * DECKX);
  assert.equal(balance.utxoCount, 1);
  assert.equal(wallet.knows(target.address), true);
});

test('the wallet finds coins beyond the first address, up to the gap limit', () => {
  const wallet = walletFrom();
  const { chain, miner } = rig('wallet/gap');

  // Pay the 15th receiving address — well past the first, inside the gap.
  const far = wallet.hd.receiving(15);
  const coin = pickUtxo(chain, miner.address);
  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: (3n * DECKX).toString(), address: far.address },
        { value: (coin.value - 3n * DECKX - 1000n).toString(), address: miner.address },
      ],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );
  chain.mineBlock([tx], miner.address, { time: chain.tip.header.time + 600 });

  assert.equal(wallet.balance(chain.state, chain.height).total, 3n * DECKX);
  assert.ok(GAP_LIMIT >= 20);
});

test('an immature coinbase is visible but not spendable', () => {
  const wallet = walletFrom();
  const { chain } = rig('wallet/immature');
  const target = wallet.hd.receiving(0);

  // Mine one block straight to the wallet, then look at it immediately.
  chain.mineBlock([], target.address, { time: chain.tip.header.time + 600 });

  const balance = wallet.balance(chain.state, chain.height);
  assert.ok(balance.total > 0n);
  assert.equal(balance.spendable, 0n, 'a fresh coinbase must not be spendable');
  assert.equal(balance.immature, balance.total);

  const attempt = wallet.send({ ...view(chain), to: wallet.hd.receiving(1).address, amount: 1n });
  assert.equal(attempt.ok, false);
  assert.match(attempt.error!, /still maturing/);

  // After maturity it becomes spendable.
  advance(chain, wallet.hd.receiving(5).address, COINBASE_MATURITY);
  assert.ok(wallet.balance(chain.state, chain.height).spendable > 0n);
});

/* ─────────────────────────────────────────────────────────── sending ── */

test('a payment is built, signed, and accepted by the chain', () => {
  const wallet = walletFrom();
  const { chain, miner } = fundedChain(wallet, 10n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const built = wallet.send({ ...view(chain), to: payee.address, amount: 3n * DECKX, memo: 'first payment' });
  assert.equal(built.ok, true, built.error);
  assert.ok(built.transaction);
  assert.ok(built.fee! > 0n);

  const mined = chain.mineBlock([built.transaction!], miner.address, {
    time: chain.tip.header.time + 600,
  });
  assert.deepEqual(mined.rejected, []);
  assert.equal(mined.result.ok, true, mined.result.error);

  assert.equal(chain.state.balanceOf(payee.address), 3n * DECKX);
  assert.equal(wallet.balance(chain.state, chain.height).total, 10n * DECKX - 3n * DECKX - built.fee!);
  assert.equal(chain.auditSupply().balanced, true);
});

test('CHANGE: the change output goes back to an address this wallet controls', () => {
  const wallet = walletFrom();
  const { chain, miner } = fundedChain(wallet, 10n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const built = wallet.send({ ...view(chain), to: payee.address, amount: 1n * DECKX });
  assert.equal(built.ok, true, built.error);

  // The single most expensive wallet bug in history is change sent nowhere.
  assert.ok(built.changeAddress, 'a payment this size must produce change');
  assert.equal(wallet.knows(built.changeAddress!), true, 'change must be to a key we hold');

  const changeOutput = built.transaction!.outputs.find((o) => o.address === built.changeAddress);
  assert.ok(changeOutput);
  assert.equal(
    BigInt(changeOutput!.value),
    10n * DECKX - 1n * DECKX - built.fee!,
    'change must be exactly the remainder',
  );

  chain.mineBlock([built.transaction!], miner.address, { time: chain.tip.header.time + 600 });

  // And the wallet can see and spend it afterwards.
  const after = wallet.balance(chain.state, chain.height);
  assert.equal(after.total, 10n * DECKX - 1n * DECKX - built.fee!);
  assert.equal(after.spendable, after.total);
});

test('change is never reused — a second payment picks a fresh change address', () => {
  const wallet = walletFrom();
  const { chain, miner } = fundedChain(wallet, 20n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const first = wallet.send({ ...view(chain), to: payee.address, amount: 1n * DECKX });
  chain.mineBlock([first.transaction!], miner.address, { time: chain.tip.header.time + 600 });

  const second = wallet.send({ ...view(chain), to: payee.address, amount: 1n * DECKX });
  assert.equal(second.ok, true, second.error);
  assert.notEqual(second.changeAddress, first.changeAddress, 'change addresses must not repeat');
});

test('dust-sized change is given to the miner rather than littering the UTXO set', () => {
  const wallet = walletFrom();
  const { chain, miner } = fundedChain(wallet, 5n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  // Pay almost everything, leaving less than the dust threshold behind.
  const size = BigInt(estimateSize(1, 1));
  const amount = 5n * DECKX - size * 2n - DUST_THRESHOLD / 2n;

  const built = wallet.send({ ...view(chain), to: payee.address, amount });
  assert.equal(built.ok, true, built.error);
  assert.equal(built.changeAddress, undefined, 'dust change must not become an output');
  assert.equal(built.transaction!.outputs.length, 1);

  const mined = chain.mineBlock([built.transaction!], miner.address, {
    time: chain.tip.header.time + 600,
  });
  assert.equal(mined.result.ok, true, mined.result.error);
  assert.equal(chain.auditSupply().balanced, true);
});

test('a sweep empties the wallet and pays the fee from the total', () => {
  const wallet = walletFrom();
  const { chain, miner } = fundedChain(wallet, 8n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const built = wallet.send({ ...view(chain), to: payee.address, amount: 0n, sweep: true });
  assert.equal(built.ok, true, built.error);
  assert.equal(built.transaction!.outputs.length, 1);
  assert.equal(built.changeAddress, undefined);

  chain.mineBlock([built.transaction!], miner.address, { time: chain.tip.header.time + 600 });

  assert.equal(chain.state.balanceOf(payee.address), 8n * DECKX - built.fee!);
  assert.equal(wallet.balance(chain.state, chain.height).total, 0n, 'a sweep must leave nothing');
});

test('spending more than the wallet holds fails with a useful message', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet, 2n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const built = wallet.send({ ...view(chain), to: payee.address, amount: 100n * DECKX });
  assert.equal(built.ok, false);
  assert.match(built.error!, /insufficient funds/);
  assert.match(built.error!, /have 2\.00000000 DECKX/);
});

test('malformed requests are refused before anything is signed', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet);

  assert.match(wallet.send({ ...view(chain), to: 'not-an-address', amount: 1n }).error!, /not a valid/);
  assert.match(wallet.send({ ...view(chain), to: wallet.hd.receiving(1).address, amount: 0n }).error!, /must be positive/);
  assert.match(
    wallet.send({ ...view(chain), to: wallet.hd.receiving(1).address, amount: -5n }).error!,
    /must be positive/,
  );
});

test('a higher fee rate produces a higher fee on the same payment', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet, 10n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  const cheap = wallet.send({ ...view(chain), to: payee.address, amount: DECKX, feeRate: 1 });
  const dear = wallet.send({ ...view(chain), to: payee.address, amount: DECKX, feeRate: 10 });

  assert.equal(cheap.ok, true, cheap.error);
  assert.equal(dear.ok, true, dear.error);
  assert.ok(dear.fee! > cheap.fee!, 'fee must scale with the requested rate');
  assert.ok(cheap.sizeBytes! <= estimateSize(cheap.inputs!.length, 2), 'the size estimate must not undershoot');
});

/* ─────────────────────────────────────────────────── coin selection ── */

test('coin selection prefers a single sufficient input', () => {
  const wallet = walletFrom();
  const { chain, miner } = rig('wallet/selection');

  // Give the wallet four separate coins of different sizes.
  let coin = pickUtxo(chain, miner.address);
  const sizes = [1n * DECKX, 5n * DECKX, 2n * DECKX, 9n * DECKX];
  const outputs = sizes.map((v, i) => ({ value: v.toString(), address: wallet.hd.receiving(i).address }));
  const spent = sizes.reduce((s, v) => s + v, 0n);
  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [...outputs, { value: (coin.value - spent - 1000n).toString(), address: miner.address }],
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );
  chain.mineBlock([tx], miner.address, { time: chain.tip.header.time + 600 });
  assert.equal(wallet.balance(chain.state, chain.height).total, spent);

  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);
  const built = wallet.send({ ...view(chain), to: payee.address, amount: 15n * DECKX / 10n });

  assert.equal(built.ok, true, built.error);
  assert.equal(built.inputs!.length, 1, 'one input suffices and should be chosen');
  assert.equal(built.inputs![0].value, 2n * DECKX, 'the smallest sufficient coin, not the largest');
});

test('a payment larger than any single coin combines inputs', () => {
  const wallet = walletFrom();
  const { chain, miner } = rig('wallet/combine');

  const coin = pickUtxo(chain, miner.address);
  const sizes = [2n * DECKX, 3n * DECKX, 4n * DECKX];
  const outputs = sizes.map((v, i) => ({ value: v.toString(), address: wallet.hd.receiving(i).address }));
  const spent = sizes.reduce((s, v) => s + v, 0n);
  chain.mineBlock(
    [
      signTx(
        transferTx({
          inputs: [{ txid: coin.txid, vout: coin.vout }],
          outputs: [...outputs, { value: (coin.value - spent - 1000n).toString(), address: miner.address }],
        }),
        miner,
        [{ value: coin.value, address: coin.address }],
      ),
    ],
    miner.address,
    { time: chain.tip.header.time + 600 },
  );

  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);
  const built = wallet.send({ ...view(chain), to: payee.address, amount: 8n * DECKX });
  assert.equal(built.ok, true, built.error);
  assert.ok(built.inputs!.length >= 2, 'must combine coins to reach the amount');

  const mined = chain.mineBlock([built.transaction!], miner.address, {
    time: chain.tip.header.time + 600,
  });
  assert.equal(mined.result.ok, true, mined.result.error);
});

test('the oldest-first strategy picks the oldest coin', () => {
  const wallet = walletFrom();
  const { chain, miner } = rig('wallet/oldest');

  // Two coins, mined into different blocks so their heights differ.
  for (let i = 0; i < 2; i++) {
    const coin = pickUtxo(chain, miner.address);
    chain.mineBlock(
      [
        signTx(
          transferTx({
            inputs: [{ txid: coin.txid, vout: coin.vout }],
            outputs: [
              { value: (4n * DECKX).toString(), address: wallet.hd.receiving(i).address },
              { value: (coin.value - 4n * DECKX - 1000n).toString(), address: miner.address },
            ],
          }),
          miner,
          [{ value: coin.value, address: coin.address }],
        ),
      ],
      miner.address,
      { time: chain.tip.header.time + 600 },
    );
  }

  const utxos = wallet.scan(chain.state, chain.height);
  assert.equal(utxos.length, 2);
  const oldest = [...utxos].sort((a, b) => a.height - b.height)[0];

  const selection = wallet.select(utxos, 1n * DECKX, COIN_STRATEGY.OLDEST_FIRST);
  assert.equal(selection.chosen[0].height, oldest.height);
});

/* ────────────────────────────────────────────────────────── recovery ── */

test('RECOVERY: a wallet rebuilt from the words alone finds its coins', () => {
  const mnemonic = generateMnemonic();
  const original = new Wallet({ hd: HdWallet.fromMnemonic(mnemonic) });
  const { chain, miner } = fundedChain(original, 12n * DECKX);

  // Spend once, so there is change on the change branch too.
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);
  const spend = original.send({ ...view(chain), to: payee.address, amount: 2n * DECKX });
  chain.mineBlock([spend.transaction!], miner.address, { time: chain.tip.header.time + 600 });

  const expected = original.balance(chain.state, chain.height);
  assert.ok(expected.total > 0n);

  // Now throw the wallet away entirely and rebuild from the twenty-four words.
  const recovered = new Wallet({ hd: HdWallet.fromMnemonic(mnemonic) });
  const found = recovered.balance(chain.state, chain.height);

  assert.equal(found.total, expected.total, 'recovery must find every coin, including change');
  assert.equal(found.utxoCount, expected.utxoCount);

  // And it can spend them.
  const after = recovered.send({ ...view(chain), to: payee.address, amount: 1n * DECKX });
  assert.equal(after.ok, true, after.error);
  const mined = chain.mineBlock([after.transaction!], miner.address, {
    time: chain.tip.header.time + 600,
  });
  assert.equal(mined.result.ok, true, mined.result.error);
});

test('a wallet from a different mnemonic sees nothing', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet, 5n * DECKX);

  const stranger = new Wallet({ hd: HdWallet.fromMnemonic(generateMnemonic()) });
  assert.equal(stranger.balance(chain.state, chain.height).total, 0n);
  assert.equal(stranger.knows(wallet.hd.receiving(0).address), false);
});

/* ────────────────────────────────────────────────────────── reporting ── */

test('the summary reports what the chain actually holds', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet, 6n * DECKX);
  const summary = wallet.summary(chain.state, chain.height);

  assert.equal(BigInt(summary.balance), 6n * DECKX);
  assert.equal(summary.balancePretty, formatDeckx(6n * DECKX));
  assert.equal(summary.utxos, 1);
  assert.equal(summary.fingerprint.length, 8);

  const history = wallet.history(chain.state, chain.height);
  assert.equal(history.length, 1);
  assert.equal(history[0].received, 6n * DECKX);
  assert.ok(history[0].confirmations >= 1);
  void txid;
});

test('the size estimate never undershoots a real transaction', () => {
  const wallet = walletFrom();
  const { chain } = fundedChain(wallet, 10n * DECKX);
  const payee = HdWallet.fromMnemonic(generateMnemonic()).receiving(0);

  // Under-estimating means paying below the intended rate, which at best
  // confirms late. The estimate is deliberately generous.
  const built = wallet.send({ ...view(chain), to: payee.address, amount: DECKX });
  assert.equal(built.ok, true, built.error);
  assert.ok(
    built.sizeBytes! <= estimateSize(built.inputs!.length, 2),
    `real ${built.sizeBytes} exceeded estimate ${estimateSize(built.inputs!.length, 2)}`,
  );
});
