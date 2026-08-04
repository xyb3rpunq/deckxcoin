#!/usr/bin/env node
/**
 * deckx-wallet — the command-line wallet.
 *
 *   node src/wallet-cli.ts new
 *   node src/wallet-cli.ts address
 *   node src/wallet-cli.ts balance
 *   node src/wallet-cli.ts send --to dxc1q… --amount 1.5
 *
 * ── What this talks to ────────────────────────────────────────────────────
 * A node, over JSON-RPC. The wallet holds keys and builds transactions; it
 * never holds a chain. That split is deliberate — a wallet that carried its own
 * copy of the UTXO set would have to sync, and a wallet that trusts a node it
 * did not verify is at least honest about doing so.
 *
 * The node is asked one question per derived address (`listunspent`), and the
 * answers are loaded into a real `WorldState`. Everything after that is the
 * ordinary `Wallet` class, unmodified: the same coin selection, the same change
 * handling, and the same dry-run through the chain's own validator before a
 * transaction is broadcast.
 *
 * ── Where the keys live ───────────────────────────────────────────────────
 * In a file you name, holding twenty-four words, mode 0600. There is no
 * encryption at rest — that is a real gap and it is stated here rather than
 * implied away. Anyone who can read the file can spend the coins.
 *
 * The words are never printed except by `new` and `export`, never logged, and
 * never sent to the node. What reaches the node is a signed transaction.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';

import { HdWallet, generateMnemonic, validateMnemonic, normaliseMnemonic } from './wallet/hd.ts';
import { Wallet, DUST_THRESHOLD } from './wallet/wallet.ts';
import { WorldState, type Utxo } from './state.ts';
import { formatDeckx, txid, ZAPS_PER_DECKX } from './tx.ts';
import { isValidAddress, normaliseAddress } from './crypto.ts';
import { rpcCall } from './node/rpc.ts';
import { networkByName } from './params.ts';

/* ─────────────────────────────────────────────────────────────── output ── */

const isTty = process.stdout.isTTY;
const paint = (code: string) => (s: string) => (isTty ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = paint('2');
const bold = paint('1');
const green = paint('32');
const red = paint('31');
const amber = paint('33');

const row = (k: string, v: string) => console.log(`  ${dim(k.padEnd(14))} ${v}`);
const fail = (message: string): never => {
  console.error(`${red('error:')} ${message}`);
  process.exit(1);
};

/* ────────────────────────────────────────────────────────────────── args ── */

interface Args {
  readonly command: string;
  readonly rest: readonly string[];
  one(name: string, fallback?: string): string | undefined;
  has(name: string): boolean;
  number(name: string, fallback: number): number;
}

function parseArgs(argv: readonly string[]): Args {
  const flags = new Map<string, string>();
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const [name, inline] = token.slice(2).split('=', 2);
    const next = argv[i + 1];
    flags.set(name, inline ?? (next && !next.startsWith('--') ? argv[++i] : ''));
  }

  return {
    command: positional[0] ?? 'help',
    rest: positional.slice(1),
    one: (name, fallback) => flags.get(name) || fallback,
    has: (name) => flags.has(name),
    number: (name, fallback) => {
      const raw = flags.get(name);
      const parsed = raw === undefined ? NaN : Number(raw);
      return Number.isFinite(parsed) ? parsed : fallback;
    },
  };
}

/* ──────────────────────────────────────────────────────────── key files ── */

const DEFAULT_WALLET = resolve(homedir(), '.deckxcoin', 'wallet.key');

function walletPath(args: Args): string {
  return resolve(args.one('wallet', DEFAULT_WALLET)!);
}

function readMnemonic(path: string): string {
  if (!existsSync(path)) {
    fail(
      `no wallet at ${path}\n` +
        `  create one with:  node src/wallet-cli.ts new\n` +
        `  or point at one:  --wallet /path/to/wallet.key`,
    );
  }
  // Comment lines let a wallet file carry a note about which chain it is for
  // without the words becoming unreadable.
  const words = readFileSync(path, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .join(' ');

  const mnemonic = normaliseMnemonic(words);
  if (!validateMnemonic(mnemonic)) {
    fail(
      `the words in ${path} do not form a valid BIP-39 mnemonic.\n` +
        `  The checksum is what catches a mistyped word — without it you would\n` +
        `  silently open a different, empty wallet.`,
    );
  }
  return mnemonic;
}

function writeMnemonic(path: string, mnemonic: string, network: string): void {
  if (existsSync(path)) {
    fail(`${path} already exists — refusing to overwrite a key file.\nMove it aside first if you really mean to.`);
  }
  mkdirSync(dirname(path), { recursive: true });
  // Written 0600 from the start rather than created and tightened: the window
  // between the two is a window in which the words are world-readable.
  writeFileSync(path, `# DeckxCoin wallet — ${network}\n# Anyone who reads this file can spend the coins.\n${mnemonic}\n`, {
    mode: 0o600,
  });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* Windows has no POSIX mode */
  }
}

/* ─────────────────────────────────────────────────────── remote state ── */

/**
 * Build a `WorldState` from what a node reports about this wallet's addresses.
 *
 * Gap-limit discovery, done over RPC: walk each branch until `gapLimit`
 * consecutive addresses come back with nothing. Stopping at the first empty
 * address would miss coins sent to a gap, which happens routinely because
 * addresses are handed out faster than they are paid.
 *
 * Only this wallet's own outputs are loaded. That is enough for balance,
 * selection, and the dry run — every input a transaction spends belongs to the
 * wallet by definition.
 */
async function fetchState(
  rpc: string,
  hd: HdWallet,
  gapLimit: number,
): Promise<{ state: WorldState; height: number; time: number; scanned: number }> {
  const info = (await rpcCall(rpc, 'getblockchaininfo')) as { height: number; tip: string };
  const tip = (await rpcCall(rpc, 'getblockheader', { hash: info.tip })) as { time: number };

  const state = new WorldState();
  let scanned = 0;

  for (const chain of [0, 1]) {
    let index = 0;
    let emptyRun = 0;

    while (emptyRun < gapLimit) {
      const key = hd.derive(chain, index);
      scanned++;

      const utxos = (await rpcCall(rpc, 'listunspent', { address: key.address })) as Array<{
        txid: string;
        vout: number;
        value: string;
        height: number;
        coinbase: boolean;
      }>;

      if (utxos.length === 0) {
        emptyRun++;
      } else {
        emptyRun = 0;
        for (const u of utxos) {
          state.addUtxo({
            txid: u.txid,
            vout: u.vout,
            value: BigInt(u.value),
            address: key.address,
            height: u.height,
            coinbase: u.coinbase,
          } as Utxo);
        }
      }
      index++;
      if (index > 10_000) break;
    }
  }

  return { state, height: info.height, time: tip.time, scanned };
}

/** Parse "1.5" or "1.50000000" into zaps without floating point. */
function parseAmount(input: string): bigint {
  const value = input.trim();
  if (!/^\d+(\.\d{1,8})?$/.test(value)) {
    fail(`'${input}' is not an amount. Use DECKX, up to 8 decimals — for example 1.5 or 0.00012345`);
  }
  const [whole, frac = ''] = value.split('.');
  return BigInt(whole) * ZAPS_PER_DECKX + BigInt(frac.padEnd(8, '0'));
}

/* ───────────────────────────────────────────────────────────── commands ── */

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const params = networkByName(args.one('network', 'regtest')!);
  const rpc = args.one('rpc', `http://127.0.0.1:${params.defaultRpcPort}`)!;
  const gapLimit = args.number('gap-limit', 20);

  const openWallet = () => {
    const path = walletPath(args);
    return { path, wallet: new Wallet({ hd: HdWallet.fromMnemonic(readMnemonic(path)), gapLimit }) };
  };

  const withNode = async (wallet: Wallet) => {
    try {
      return await fetchState(rpc, wallet.hd, gapLimit);
    } catch (err) {
      return fail(
        `could not reach a node at ${rpc}\n` +
          `  ${(err as Error).message}\n\n` +
          `  Start one with:\n` +
          `    node src/deckxd.ts --network ${params.name} --datadir ./data/${params.name}`,
      );
    }
  };

  switch (args.command) {
    /* ── new ─────────────────────────────────────────────────────────── */
    case 'new': {
      const path = walletPath(args);
      const mnemonic = generateMnemonic();
      writeMnemonic(path, mnemonic, params.name);

      const wallet = new Wallet({ hd: HdWallet.fromMnemonic(mnemonic), gapLimit });
      console.log(bold('\nA new wallet.\n'));
      row('file', path);
      row('network', params.name);
      row('fingerprint', wallet.hd.fingerprint());
      row('address', wallet.hd.receiving(0).address);
      console.log(`\n${bold('Write these twenty-four words down, offline:')}\n`);
      console.log(`  ${mnemonic.split(' ').slice(0, 12).join(' ')}`);
      console.log(`  ${mnemonic.split(' ').slice(12).join(' ')}\n`);
      console.log(
        amber('  They are the only way to recover this wallet. Nobody can reset them,\n') +
          amber('  and anyone who reads them can spend the coins.\n'),
      );
      return 0;
    }

    /* ── restore ─────────────────────────────────────────────────────── */
    case 'restore': {
      const words = args.one('words');
      if (!words) fail('restore needs --words "twenty four words in quotes"');
      const mnemonic = normaliseMnemonic(words!);
      if (!validateMnemonic(mnemonic)) {
        fail('those words fail the BIP-39 checksum — one of them is wrong or out of order');
      }
      const path = walletPath(args);
      writeMnemonic(path, mnemonic, params.name);

      const wallet = new Wallet({ hd: HdWallet.fromMnemonic(mnemonic), gapLimit });
      console.log(bold('\nWallet restored.\n'));
      row('file', path);
      row('fingerprint', wallet.hd.fingerprint());
      row('address', wallet.hd.receiving(0).address);
      console.log();
      return 0;
    }

    /* ── address ─────────────────────────────────────────────────────── */
    case 'address': {
      const { wallet } = openWallet();
      // A fresh address per payment. Reusing one links every payment you have
      // ever received, and rotation is the largest privacy gain a wallet has.
      if (args.has('offline')) {
        console.log(wallet.hd.receiving(0).address);
        return 0;
      }
      const { state } = await withNode(wallet);
      console.log(wallet.nextReceiveAddress(state).address);
      return 0;
    }

    /* ── balance ─────────────────────────────────────────────────────── */
    case 'balance': {
      const { wallet, path } = openWallet();
      const { state, height, scanned } = await withNode(wallet);
      const balance = wallet.balance(state, height);

      console.log(bold(`\n${params.name} · height ${height}\n`));
      row('wallet', path);
      row('fingerprint', wallet.hd.fingerprint());
      row('total', formatDeckx(balance.total));
      row('spendable', green(formatDeckx(balance.spendable)));
      if (balance.immature > 0n) {
        row('immature', amber(`${formatDeckx(balance.immature)} (coinbase, still maturing)`));
      }
      row('utxos', String(balance.utxoCount));
      row('scanned', `${scanned} addresses (gap limit ${gapLimit})`);
      console.log();
      return 0;
    }

    /* ── send ────────────────────────────────────────────────────────── */
    case 'send': {
      const toRaw = args.one('to');
      if (!toRaw) fail('send needs --to <address>');
      const to = normaliseAddress(toRaw!);
      if (!isValidAddress(to)) fail(`'${toRaw}' is not a valid DeckxCoin address`);

      const sweep = args.has('sweep');
      const amountRaw = args.one('amount');
      if (!sweep && !amountRaw) fail('send needs --amount <DECKX>, or --sweep to send everything');
      const amount = sweep ? 0n : parseAmount(amountRaw!);
      if (!sweep && amount <= 0n) fail('amount must be positive');
      if (!sweep && amount < DUST_THRESHOLD) {
        fail(`${formatDeckx(amount)} is below the dust threshold of ${DUST_THRESHOLD} zaps`);
      }

      const { wallet } = openWallet();
      const { state, height, time } = await withNode(wallet);

      const built = wallet.send({
        state,
        tipHeight: height,
        tipTime: time,
        to,
        amount,
        sweep,
        feeRate: args.number('fee-rate', wallet.feeRate),
        memo: args.one('memo'),
      });

      if (!built.ok) fail(built.error!);

      const paid = built.transaction!.outputs.find((o) => o.address === to)!;
      const id = txid(built.transaction!);

      console.log(bold('\nReady to send.\n'));
      row('to', to);
      row('amount', formatDeckx(BigInt(paid.value)));
      row('fee', `${built.fee} zaps (${built.sizeBytes} bytes)`);
      if (built.changeAddress) row('change to', `${built.changeAddress} ${dim('(your own wallet)')}`);
      row('txid', id);

      if (args.has('dry-run')) {
        console.log(`\n${amber('  --dry-run: nothing was broadcast.')}\n`);
        return 0;
      }

      try {
        const result = (await rpcCall(rpc, 'sendrawtransaction', {
          transaction: built.transaction,
        })) as { txid: string };
        console.log(`\n  ${green('broadcast')} ${result.txid}`);
        console.log(dim(`  It is in the mempool. Mine a block, or wait for one, to confirm it.\n`));
      } catch (err) {
        fail(`the node rejected it: ${(err as Error).message}`);
      }
      return 0;
    }

    /* ── history ─────────────────────────────────────────────────────── */
    case 'history': {
      const { wallet } = openWallet();
      const { state, height } = await withNode(wallet);
      const entries = wallet.history(state, height);

      if (entries.length === 0) {
        console.log(dim('\n  nothing received yet\n'));
        return 0;
      }
      console.log(bold(`\n${entries.length} unspent output(s)\n`));
      console.log(dim('  height   confirmations   amount              address'));
      for (const e of entries) {
        console.log(
          `  ${String(e.height).padEnd(8)} ${String(e.confirmations).padEnd(15)} ` +
            `${formatDeckx(e.received).padEnd(24)}${dim(e.address)}`,
        );
      }
      console.log();
      return 0;
    }

    /* ── export ──────────────────────────────────────────────────────── */
    case 'export': {
      const path = walletPath(args);
      const mnemonic = readMnemonic(path);
      if (!args.has('yes')) {
        console.log(
          amber('\n  This prints your seed phrase to the terminal, where it may be kept\n') +
            amber('  in scrollback and in shell history. Re-run with --yes if you mean it.\n'),
        );
        return 1;
      }
      console.log(mnemonic);
      return 0;
    }

    /* ── info ────────────────────────────────────────────────────────── */
    case 'info': {
      const { wallet, path } = openWallet();
      console.log(bold('\nWallet\n'));
      row('file', path);
      row('network', params.name);
      row('fingerprint', wallet.hd.fingerprint());
      row('account', String(wallet.hd.account));
      row('path', `m/84'/9333'/${wallet.hd.account}'/0/0`);
      row('first address', wallet.hd.receiving(0).address);
      row('rpc', rpc);
      console.log(dim('\n  No balance shown — that needs a node. Use `balance`.\n'));
      return 0;
    }

    case 'help':
    default:
      console.log(HELP);
      return args.command === 'help' ? 0 : 1;
  }
}

const HELP = `
deckx-wallet — the DeckxCoin command-line wallet

  new                    create a wallet and print its recovery words
  restore --words "..."  rebuild a wallet from twenty-four words
  address                a fresh receiving address
  balance                what this wallet holds
  send --to A --amount N send coins
  history                unspent outputs, newest first
  info                   fingerprint and derivation path, no node needed
  export --yes           print the seed phrase (think first)

Options

  --wallet <path>    key file            (default ~/.deckxcoin/wallet.key)
  --network <name>   mainnet | testnet | regtest   (default regtest)
  --rpc <url>        node JSON-RPC       (default http://127.0.0.1:<network port>)
  --gap-limit <n>    addresses to scan past the last used one  (default 20)

send options

  --sweep            send everything, fee taken from the total
  --fee-rate <n>     zaps per byte       (default 2)
  --memo "<text>"    note in the transaction, ≤ 80 bytes
  --dry-run          build and show it, broadcast nothing

Sending coins between two wallets, start to finish

  # a node to talk to
  node src/deckxd.ts --network regtest --datadir ./data/regtest --rpcport 29332

  # two wallets
  node src/wallet-cli.ts new --wallet ./alice.key
  node src/wallet-cli.ts new --wallet ./bob.key

  # give Alice some coins by mining to her address, then 100 more blocks so
  # the coinbase matures
  ALICE=$(node src/wallet-cli.ts address --wallet ./alice.key --offline)
  curl -s localhost:29332 -d "{\\"method\\":\\"generate\\",\\"params\\":{\\"count\\":101,\\"address\\":\\"$ALICE\\"}}"

  # Alice pays Bob
  BOB=$(node src/wallet-cli.ts address --wallet ./bob.key --offline)
  node src/wallet-cli.ts send --wallet ./alice.key --to "$BOB" --amount 5

  # confirm it, then look
  curl -s localhost:29332 -d "{\\"method\\":\\"generate\\",\\"params\\":{\\"count\\":1,\\"address\\":\\"$ALICE\\"}}"
  node src/wallet-cli.ts balance --wallet ./bob.key
`;

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(red(`deckx-wallet: ${(err as Error).message}`));
    process.exit(1);
  },
);
