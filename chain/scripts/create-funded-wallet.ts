#!/usr/bin/env node
/**
 * Create a wallet and fund it on a fresh local chain.
 *
 *   node scripts/create-funded-wallet.ts --amount 1000000 --out ./WALLET.txt
 *
 * ── What this actually does, stated plainly ───────────────────────────────
 * It builds a **local regtest chain**, mines enough blocks to pay the wallet
 * the requested amount, and writes the seed phrase to a file.
 *
 * The coins exist only in the database this script creates. There is no live
 * DeckxCoin network, no exchange, and no price. These are numbers in a local
 * ledger — the same category of thing as a row in a spreadsheet you wrote
 * yourself. Anyone claiming otherwise is mistaken or lying.
 *
 * ── Secrets ───────────────────────────────────────────────────────────────
 * The output file contains the seed phrase, which *is* the wallet. Whoever
 * holds it holds the coins; there is no reset, no support line, and no way to
 * recover it if lost. The repository's `.gitignore` is written to keep files
 * like this out of version control, because this repository is public and a
 * committed secret cannot be un-committed.
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Blockchain } from '../src/chain.ts';
import { blockSubsidy } from '../src/block.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { formatDeckx, ZAPS_PER_DECKX } from '../src/tx.ts';
import { toHex } from '../src/crypto.ts';
import { HdWallet } from '../src/wallet/hd.ts';
import { Wallet } from '../src/wallet/wallet.ts';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i++) {
  const token = process.argv[i];
  if (token.startsWith('--')) args.set(token.slice(2), process.argv[i + 1] ?? '');
}

const targetCoins = BigInt(args.get('amount') ?? '1000000');
const targetZaps = targetCoins * ZAPS_PER_DECKX;
const outPath = resolve(args.get('out') ?? './DECKXCOIN-WALLET.txt');
const mnemonicWords = Number(args.get('words') ?? 24);

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

console.log(bold('\nDeckxCoin — create and fund a wallet\n'));

/* ── 1. the wallet ──────────────────────────────────────────────────── */

const { mnemonic, wallet: hd } = HdWallet.create(mnemonicWords === 12 ? 128 : 256);
const wallet = new Wallet({ hd });
const receive = hd.receiving(0);

console.log(`  ${dim('mnemonic'.padEnd(14))} ${mnemonicWords} words generated`);
console.log(`  ${dim('fingerprint'.padEnd(14))} ${hd.fingerprint()}`);
console.log(`  ${dim('address'.padEnd(14))} ${receive.address}`);
console.log(`  ${dim('path'.padEnd(14))} ${receive.path}\n`);

/* ── 2. the chain ───────────────────────────────────────────────────── */

/*
 * Regtest, so mining is instant. The consensus rules are identical to
 * mainnet's — only the proof-of-work target differs — so the coins are as
 * "real" as anything on this chain gets, which is to say: real within this
 * database and nowhere else.
 */
const chain = Blockchain.regtest();
const subsidy = blockSubsidy(0);
const blocksNeeded = Number((targetZaps + subsidy - 1n) / subsidy);


console.log(`  ${dim('target'.padEnd(14))} ${formatDeckx(targetZaps)}`);
console.log(`  ${dim('subsidy'.padEnd(14))} ${formatDeckx(subsidy)} per block`);
console.log(`  ${dim('blocks'.padEnd(14))} ${blocksNeeded} to fund + ${COINBASE_MATURITY} to mature\n`);

const started = Date.now();
let t = chain.tip.header.time;

/*
 * Consolidate as we go.
 *
 * Mining five thousand blocks straight to one wallet leaves five thousand
 * separate outputs, and the state root is recomputed over the whole UTXO set
 * for every block — so the cost is quadratic and the run takes hours. Folding
 * matured coins into a single output every few hundred blocks keeps the set
 * small and the cost roughly linear.
 *
 * Consensus is untouched. These are ordinary transactions validated by the
 * ordinary rules; only the shape of the UTXO set changes.
 */
const ROUND = 300;

/** Coinbases not destined for the wallet go here — outside the wallet's tree. */
const elsewhere = chain.blocks[0].transactions[0].outputs[0].address;

const mineOne = (to: string, txs: Parameters<typeof chain.mineBlock>[0] = []): void => {
  t += 600;
  const { result, rejected } = chain.mineBlock(txs, to, { time: t });
  if (!result.ok || rejected.length > 0) {
    console.error(red(`\n  block rejected: ${result.error ?? rejected[0]?.error}`));
    process.exit(1);
  }
};

/**
 * Fold every mature wallet output into one, on the wallet's primary address.
 *
 * The destination has to stay inside the wallet's own discovery range. An
 * earlier version swept to `change(height % 4096)`, an index hundreds of steps
 * past the gap limit — so the next scan walked twenty empty addresses, stopped,
 * and reported a balance of zero while the coins sat there untouched. Address
 * derivation is only useful up to where a recovering wallet will actually look.
 */
const consolidate = (): number => {
  const mature = wallet.scan(chain.state, chain.height).filter((u) => u.spendable);
  if (mature.length < 2) return 0;

  const built = wallet.send({
    state: chain.state,
    tipHeight: chain.height,
    tipTime: chain.tip.header.time,
    to: receive.address,
    amount: 0n,
    sweep: true,
    feeRate: 0,
  });
  if (!built.ok) return 0;

  mineOne(elsewhere, [built.transaction!]);
  return mature.length;
};

/*
 * Every block pays the wallet, and every round folds the matured ones into a
 * single output. The UTXO set therefore stays around one round's worth instead
 * of growing without bound.
 *
 * An earlier version mined the maturity-advancing blocks to a separate address
 * to keep the balance tidy — but those coinbases were never consolidated, so
 * the set grew by a hundred every round and the run slowed down quadratically
 * anyway. Paying everything to the wallet and trimming the excess at the end is
 * both faster and simpler.
 */
/*
 * Driven by the balance, not a block count.
 *
 * Counting blocks looks simpler and is wrong, because the maturity blocks pay
 * the wallet too — so the arithmetic has to predict how many of its own
 * side-effects it will cause. Asking the wallet what it holds is exact.
 */
while (wallet.balance(chain.state, chain.height).total < targetZaps) {
  for (let i = 0; i < ROUND; i++) mineOne(receive.address);
  // Advance past maturity so the batch just mined can be folded in. These pay
  // the wallet as well, which is fine — the next consolidation absorbs them.
  for (let i = 0; i < COINBASE_MATURITY; i++) mineOne(receive.address);
  consolidate();

  const held = wallet.balance(chain.state, chain.height);
  process.stdout.write(
    `\r  ${dim('mining'.padEnd(14))} ${formatDeckx(held.total).padStart(22)} / ` +
      `${formatDeckx(targetZaps)} · height ${chain.height} · ${chain.state.utxoCount} utxos    `,
  );
}

/*
 * The final maturity run pays somewhere else.
 *
 * Paying the wallet here would create a fresh batch of immature coinbases, and
 * the balance would never settle — every attempt to mature the last coins adds
 * new ones. This was a real bug: the trim below then computed its excess from
 * the *spendable* portion while the immature remainder was still on its way in,
 * and the wallet ended up holding several times the target.
 */
for (let i = 0; i <= COINBASE_MATURITY; i++) mineOne(elsewhere);
consolidate();

/*
 * Trim to the exact figure.
 *
 * Mining works in whole subsidies, so the wallet now holds slightly more than
 * was asked for. Send the excess away — the change returning to the wallet is
 * then exactly the target.
 */
const before = wallet.balance(chain.state, chain.height);
if (before.immature > 0n) {
  console.error(red(`\n  ${formatDeckx(before.immature)} is still immature — cannot trim exactly`));
  process.exit(1);
}
const excess = before.total - targetZaps;
if (excess > 0n) {
  const trim = wallet.send({
    state: chain.state,
    tipHeight: chain.height,
    tipTime: chain.tip.header.time,
    to: elsewhere,
    amount: excess,
    feeRate: 0,
  });
  if (!trim.ok) {
    console.error(red(`\n  could not trim to the exact amount: ${trim.error}`));
    process.exit(1);
  }
  mineOne(elsewhere, [trim.transaction!]);
  for (let i = 0; i <= COINBASE_MATURITY; i++) mineOne(elsewhere);

  // The trim left the balance as change. Move it back onto the advertised
  // address, so the figure in the wallet file sits where the file says it does.
  const gather = wallet.send({
    state: chain.state,
    tipHeight: chain.height,
    tipTime: chain.tip.header.time,
    to: receive.address,
    amount: 0n,
    sweep: true,
    feeRate: 0,
  });
  if (gather.ok) mineOne(elsewhere, [gather.transaction!]);
}

console.log(`\n  ${dim('elapsed'.padEnd(14))} ${((Date.now() - started) / 1000).toFixed(1)}s\n`);

/* ── 3. verify ──────────────────────────────────────────────────────── */

const balance = wallet.balance(chain.state, chain.height);
const audit = chain.auditSupply();

console.log(bold('  Verification\n'));
const row = (k: string, v: string) => console.log(`  ${dim(k.padEnd(14))} ${v}`);
row('height', String(chain.height));
row('total', formatDeckx(balance.total));
row('spendable', formatDeckx(balance.spendable));
row('immature', formatDeckx(balance.immature));
row('utxos', String(balance.utxoCount));
row('supply audit', audit.balanced ? green('balanced') : red('DRIFT'));
row('chain supply', formatDeckx(audit.utxoTotal));

if (!audit.balanced) {
  console.error(red('\n  supply audit failed — refusing to write a wallet file'));
  process.exit(1);
}
if (balance.spendable < targetZaps) {
  console.error(
    red(`\n  only ${formatDeckx(balance.spendable)} is spendable, wanted ${formatDeckx(targetZaps)}`),
  );
  process.exit(1);
}

/*
 * Prove the coins actually move.
 *
 * A sweep, not a fixed-amount payment: the balance is exactly the target, so
 * asking to send the target *plus* a fee is asking for more than exists. A
 * sweep takes the fee out of the total, which is the honest way to test that
 * the whole balance is spendable.
 *
 * Built and validated against the chain's rules, then discarded — the wallet
 * is handed over untouched.
 */
const proof = wallet.send({
  state: chain.state,
  tipHeight: chain.height,
  tipTime: chain.tip.header.time,
  to: elsewhere,
  amount: 0n,
  sweep: true,
  feeRate: 1,
});
row(
  'spend check',
  proof.ok
    ? green(`valid — ${formatDeckx(BigInt(proof.transaction!.outputs[0].value))} movable, fee ${proof.fee} zaps`)
    : red(proof.error ?? 'failed'),
);
if (!proof.ok) process.exit(1);

/* ── 4. write the secret ────────────────────────────────────────────── */

const now = new Date().toISOString();
const content = `DECKXCOIN WALLET
================================================================================
Generated ${now}

################################################################################
#  THIS FILE IS THE WALLET.                                                    #
#                                                                              #
#  Anyone who reads the recovery phrase below controls these coins. There is   #
#  no reset, no support line, and no way to recover it if you lose it.         #
#                                                                              #
#  Store it offline. Do not photograph it, do not put it in cloud storage,     #
#  do not paste it into a website, and do not commit it to a git repository.   #
################################################################################

--------------------------------------------------------------------------------
RECOVERY PHRASE (${mnemonic.split(' ').length} words) — this alone restores the whole wallet
--------------------------------------------------------------------------------

${mnemonic
  .split(' ')
  .map((w, i) => `${String(i + 1).padStart(2, ' ')}. ${w}`)
  .reduce((rows: string[][], entry, i) => {
    const row = Math.floor(i / 4);
    rows[row] = rows[row] ?? [];
    rows[row].push(entry.padEnd(16));
    return rows;
  }, [])
  .map((row) => '    ' + row.join(''))
  .join('\n')}

    Plain form (for pasting into a wallet):

    ${mnemonic}

--------------------------------------------------------------------------------
FIRST ACCOUNT
--------------------------------------------------------------------------------

    Derivation path      ${receive.path}
    Address              ${receive.address}
    Private key (hex)    ${toHex(receive.privateKey)}
    Public key (x-only)  ${toHex(receive.publicKey)}
    Master fingerprint   ${hd.fingerprint()}
    Account xpub         ${hd.accountXpub()}

    The private key above unlocks ONLY this one address. The recovery phrase
    unlocks every address the wallet will ever derive, including change. If you
    keep only one thing, keep the phrase.

--------------------------------------------------------------------------------
BALANCE
--------------------------------------------------------------------------------

    Amount               ${formatDeckx(balance.total)}
    Spendable            ${formatDeckx(balance.spendable)}
    Outputs              ${balance.utxoCount}
    Chain                regtest (local)
    Chain height         ${chain.height}
    Genesis              ${chain.blocks[0].header.stateRoot}

--------------------------------------------------------------------------------
WHAT THESE COINS ARE, HONESTLY
--------------------------------------------------------------------------------

    These coins exist on a LOCAL chain generated by this script and nowhere
    else. DeckxCoin has no live network, no exchange listing, and no price.
    DECKX is not for sale and cannot be bought or sold.

    This is a reference implementation and a teaching artefact. The balance
    above is real in exactly the way a number in your own spreadsheet is real.
    Do not treat it as an asset, and do not let anyone tell you it is one.

--------------------------------------------------------------------------------
RESTORING
--------------------------------------------------------------------------------

    git clone https://github.com/xyb3rpunq/deckxcoin.git
    cd deckxcoin/chain && npm install
    node src/cli.ts wallet-restore "<your recovery phrase>"

================================================================================
`;

writeFileSync(outPath, content, { encoding: 'utf8', mode: 0o600 });

console.log(bold(`\n  Wallet written to ${outPath}`));
console.log(red('  This file contains the recovery phrase. Move it somewhere safe, then delete it.\n'));

// Best-effort wipe of the in-process key material. JavaScript offers no real
// guarantee here — the runtime may have copied the buffer — so a process that
// has held a key should be assumed compromised if the machine is.
hd.wipe();
