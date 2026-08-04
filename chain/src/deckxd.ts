#!/usr/bin/env node
/**
 * deckxd — the DeckxCoin node daemon.
 *
 *   node src/deckxd.ts --network testnet --datadir ./data/node1 \
 *        --port 19333 --rpcport 19332 --connect 127.0.0.1:19334 --mine <address>
 *
 * Flags:
 *   --network    mainnet | testnet | regtest        (default regtest)
 *   --datadir    directory for chain.sqlite          (default ./data/<network>)
 *   --port       P2P listen port                     (network default)
 *   --rpcport    JSON-RPC port                       (network default)
 *   --host       P2P bind address                    (default 127.0.0.1)
 *   --connect    peer to dial, repeatable            (host:port)
 *   --mine       address to mine to; omit to run as a non-mining node
 *   --mine-interval  seconds between mining attempts (default 10)
 *   --no-listen  make outbound connections only
 *   --quiet      suppress the periodic status line
 *
 * The process runs until interrupted. SIGINT and SIGTERM close the database
 * cleanly — killing a node mid-write is the one way to corrupt its datadir.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { DeckxNode } from './node/node.ts';
import { RpcServer } from './node/rpc.ts';
import { Gateway } from './node/gateway.ts';
import { Faucet, FaucetLedger, DEFAULT_POLICY } from './node/faucet.ts';
import { HdWallet, generateMnemonic } from './wallet/hd.ts';
import { Wallet } from './wallet/wallet.ts';
import { networkByName } from './params.ts';
import { isValidAddress, normaliseAddress, toHex } from './crypto.ts';
import { formatDeckx, ZAPS_PER_DECKX } from './tx.ts';

interface Args {
  readonly flags: Map<string, string[]>;
  has(name: string): boolean;
  one(name: string, fallback?: string): string | undefined;
  many(name: string): string[];
  number(name: string, fallback: number): number;
}

function parseArgs(argv: readonly string[]): Args {
  const flags = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const [name, inline] = token.slice(2).split('=', 2);
    const value = inline ?? (argv[i + 1]?.startsWith('--') ? '' : (argv[++i] ?? ''));
    const list = flags.get(name) ?? [];
    list.push(value);
    flags.set(name, list);
  }
  return {
    flags,
    has: (name) => flags.has(name),
    one: (name, fallback) => flags.get(name)?.[0] || fallback,
    many: (name) => (flags.get(name) ?? []).filter(Boolean),
    number: (name, fallback) => {
      const raw = flags.get(name)?.[0];
      const parsed = raw === undefined ? NaN : Number(raw);
      return Number.isFinite(parsed) ? parsed : fallback;
    },
  };
}

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const stamp = () => dim(new Date().toISOString().slice(11, 19));

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));

  if (args.has('help')) {
    console.log(HELP);
    return 0;
  }

  const params = networkByName(args.one('network', 'regtest')!);
  const datadir = resolve(args.one('datadir', `./data/${params.name}`)!);
  const port = args.number('port', params.defaultPort);
  const rpcPort = args.number('rpcport', params.defaultRpcPort);
  const quiet = args.has('quiet');

  // Normalised: consensus only accepts the canonical spelling, so an
  // uppercase address from a QR code would otherwise make every mined block
  // invalid with no hint as to why.
  const mineToRaw = args.one('mine');
  const mineTo = mineToRaw ? normaliseAddress(mineToRaw) : undefined;
  if (mineTo && !isValidAddress(mineTo)) {
    console.error(red(`--mine '${mineTo}' is not a valid DeckxCoin address`));
    return 2;
  }

  const node = new DeckxNode({
    params,
    datadir,
    listenPort: port,
    listenHost: args.one('host', '127.0.0.1'),
    listen: !args.has('no-listen'),
    connect: args.many('connect'),
    userAgent: `deckxd:0.2.0/${params.name}`,
  });

  const rpc = new RpcServer({ node, port: rpcPort });

  /* ── faucet ──────────────────────────────────────────────────────── */

  let faucet: Faucet | undefined;
  let faucetPath: string | undefined;

  if (args.has('faucet')) {
    if (params.name === 'mainnet') {
      console.error(red('--faucet refuses to run on mainnet: it gives coins to anyone who asks'));
      return 2;
    }

    faucetPath = resolve(args.one('faucet-wallet', `${datadir}/faucet.key`)!);
    const ledgerPath = `${faucetPath}.ledger.json`;
    const mnemonic = loadOrCreateMnemonic(faucetPath);

    const wallet = new Wallet({ hd: HdWallet.fromMnemonic(mnemonic) });
    const ledger = existsSync(ledgerPath)
      ? FaucetLedger.fromJSON(JSON.parse(readFileSync(ledgerPath, 'utf8')))
      : new FaucetLedger();

    const deckx = (name: string, fallback: bigint): bigint => {
      const raw = args.one(name);
      if (raw === undefined) return fallback;
      const value = Number(raw);
      if (!Number.isFinite(value) || value < 0) throw new Error(`--${name} must be a number of DECKX`);
      return BigInt(Math.round(value * Number(ZAPS_PER_DECKX)));
    };

    faucet = new Faucet({
      wallet,
      chain: () => ({
        state: node.chain.state,
        height: node.chain.height,
        // The persistent node's chain is a ChainState, which stores headers
        // rather than whole blocks — the tip's timestamp comes from the header
        // index, not from a Block object.
        time: node.chain.headerAt(node.chain.height)?.time ?? Math.floor(Date.now() / 1000),
      }),
      broadcast: (tx) => {
        const result = node.submitTransaction(tx);
        if (!result.ok) return { ok: false, error: result.error };
        node.relayTransaction(tx);
        return { ok: true };
      },
      policy: {
        amount: deckx('faucet-amount', DEFAULT_POLICY.amount),
        reserve: deckx('faucet-reserve', DEFAULT_POLICY.reserve),
        dailyCap: deckx('faucet-daily-cap', DEFAULT_POLICY.dailyCap),
        addressCooldownMs: args.number('faucet-cooldown', 60) * 60_000,
      },
      ledger,
      // Persisted on every grant. A faucet that forgets on restart is one you
      // drain by crashing it.
      onChange: (l) => {
        try {
          writeFileSync(ledgerPath, JSON.stringify(l.toJSON()), { mode: 0o600 });
        } catch (err) {
          console.error(`${stamp()} ${red('faucet')}    could not persist ledger: ${(err as Error).message}`);
        }
      },
    });
  }

  /* ── public gateway ──────────────────────────────────────────────── */

  let gateway: Gateway | undefined;
  if (args.has('gateway') || args.has('gateway-port')) {
    gateway = new Gateway({
      // No HTTP hop: the gateway calls the RPC dispatcher directly, so the
      // node's own port stays on loopback where it belongs.
      call: async (method, callParams) => rpc.call(method, callParams),
      port: args.number('gateway-port', 8080),
      host: args.one('gateway-host', '0.0.0.0'),
      ratePerMinute: args.number('gateway-rate', 60),
      trustProxy: args.number('gateway-trust-proxy', 0),
      faucet,
    });
  }

  /* ── logging ─────────────────────────────────────────────────────── */

  node.on('peerReady', (peer) => {
    console.log(`${stamp()} ${green('peer')}      ${peer.id} ${dim(`${peer.userAgent} height=${peer.height}`)}`);
  });
  node.on('peerGone', (peer, reason) => {
    console.log(`${stamp()} ${dim('peer gone')} ${peer.id} ${dim(reason)}`);
  });
  node.on('banned', (detail: { host: string; reason: string }) => {
    console.log(`${stamp()} ${red('banned')}    ${detail.host} ${dim(detail.reason)}`);
  });
  node.on('tip', (tip: { height: number; hash: string }) => {
    console.log(`${stamp()} ${bold('tip')}       ${tip.height} ${dim(tip.hash.slice(0, 20) + '…')}`);
  });
  node.on('reorg', (reorg: { disconnected: string[]; connected: string[] }) => {
    console.log(
      `${stamp()} ${red('reorg')}     -${reorg.disconnected.length} +${reorg.connected.length} blocks`,
    );
  });
  node.on('error', (err: Error) => console.error(`${stamp()} ${red('error')}     ${err.message}`));

  /* ── start ───────────────────────────────────────────────────────── */

  await node.start();
  await rpc.start();
  if (gateway) await gateway.start();

  console.log(bold(`\ndeckxd — ${params.name}\n`));
  const row = (k: string, v: string) => console.log(`  ${dim(k.padEnd(12))} ${v}`);
  row('datadir', datadir);
  row('p2p', `${args.one('host', '127.0.0.1')}:${port}`);
  row('rpc', `http://127.0.0.1:${rpcPort}`);
  if (gateway) row('gateway', `http://${gateway.host}:${gateway.port}`);
  row('genesis', node.chain.headerAt(0)!.hash);
  row('height', String(node.chain.height));
  row('supply', formatDeckx(node.chain.auditSupply().utxoTotal));
  if (mineTo) row('mining to', mineTo);
  if (faucet) {
    const info = faucet.info();
    row('faucet', `${info.address} ${dim(`(${info.balancePretty})`)}`);
    row('faucet key', faucetPath!);
    if (!info.healthy) {
      console.log(
        `\n  ${red('the faucet is empty')} — mine to its address, or fund it from another wallet:\n` +
          `  ${dim(`--mine ${info.address}`)}`,
      );
    }
  }
  console.log();

  /*
   * The identity is what a newcomer pins to detect an interposed peer. It is
   * only useful if the operator publishes it, so it is printed where they will
   * see it rather than buried in a datadir.
   */
  if (args.one('host', '127.0.0.1') !== '127.0.0.1') {
    /*
     * The hex public key, not the bech32 address. `--connect` parses
     * `host:port#<64 lowercase hex>` — see `parsePeerAddress` — and the wire
     * proves identity with `toHex(publicKey)`. Publishing the address would
     * hand people a string their own node refuses to parse.
     */
    console.log(
      `  ${dim('publish this:')} ${bold(`<your-host>:${port}#${toHex(node.identity.publicKey)}`)}\n`,
    );
  }

  /* ── mining ──────────────────────────────────────────────────────── */

  let miner: NodeJS.Timeout | undefined;
  if (mineTo) {
    const intervalMs = Math.max(1, args.number('mine-interval', 10)) * 1000;
    miner = setInterval(() => {
      try {
        const res = node.mineOne(mineTo);
        if (res.accepted.status !== 'connected') {
          console.error(`${stamp()} ${red('mine')}      rejected: ${res.accepted.error}`);
        } else if (res.rejected.length > 0) {
          console.log(`${stamp()} ${dim('mine')}      dropped ${res.rejected.length} unusable tx`);
        }
      } catch (err) {
        console.error(`${stamp()} ${red('mine')}      ${(err as Error).message}`);
      }
    }, intervalMs);
  }

  /* ── periodic status ─────────────────────────────────────────────── */

  let status: NodeJS.Timeout | undefined;
  if (!quiet) {
    status = setInterval(() => {
      const info = node.info();
      console.log(
        `${stamp()} ${dim('status')}    height=${info.height} peers=${info.peers} ` +
          `mempool=${info.mempool.count} supply=${info.supplyBalanced ? 'ok' : red('DRIFT')}`,
      );
    }, 60_000);
    status.unref?.();
  }

  /* ── shutdown ────────────────────────────────────────────────────── */

  /*
   * The one handle that keeps the daemon running.
   *
   * Every other handle in the process is deliberately unref'd — the P2P
   * listener, the RPC server, the dial timer, the status line — so that tests
   * embedding these components do not hang waiting for them. That leaves
   * nothing holding the event loop open, and `await new Promise(() => {})`
   * holds nothing either: a promise that never settles is not a libuv handle,
   * so Node considers the loop empty and exits.
   *
   * The symptom was the worst kind: the daemon printed its banner and exited
   * with status 0, looking exactly like a successful start. Under systemd it
   * would have restarted every five seconds forever.
   *
   * So the daemon owns its own lifetime explicitly, with a ref'd timer that
   * shutdown clears.
   */
  const keepAlive = setInterval(() => {}, 1 << 30);

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${stamp()} ${dim(signal)} — closing`);
    clearInterval(keepAlive);
    if (miner) clearInterval(miner);
    if (status) clearInterval(status);
    if (gateway) await gateway.stop();
    await rpc.stop();
    await node.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  await new Promise(() => {});
  return 0;
}

/**
 * Read the faucet's mnemonic, creating one on first run.
 *
 * Written with mode 0600 and never logged. The address derived from it *is*
 * printed, because an operator has to know where to send the coins that fill
 * the faucet, and an address is public by nature.
 */
function loadOrCreateMnemonic(path: string): string {
  if (existsSync(path)) {
    const mnemonic = readFileSync(path, 'utf8').trim();
    if (!mnemonic) throw new Error(`faucet key file ${path} is empty`);
    return mnemonic;
  }

  mkdirSync(dirname(path), { recursive: true });
  const mnemonic = generateMnemonic();
  // Written 0600 from the start rather than created and then tightened: the
  // window between the two is a window in which the words are world-readable.
  writeFileSync(path, `${mnemonic}\n`, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Windows has no POSIX mode. The file is still in the datadir.
  }
  console.log(`${stamp()} ${bold('faucet')}    generated a new wallet at ${path}`);
  return mnemonic;
}

const HELP = `
deckxd — the DeckxCoin node daemon

  --network <name>       mainnet | testnet | regtest      (default regtest)
  --datadir <path>       chain database directory         (default ./data/<network>)
  --port <n>             P2P listen port
  --rpcport <n>          JSON-RPC port
  --host <addr>          P2P bind address                 (default 127.0.0.1)
  --connect <host:port>  dial a peer, repeatable
  --mine <address>       mine to this address
  --mine-interval <s>    seconds between attempts         (default 10)
  --no-listen            outbound connections only
  --quiet                suppress the periodic status line
  --help                 this text

Public gateway — the only port meant to face the internet. Read-only,
cached and rate-limited; the RPC above stays on loopback.

  --gateway              enable it
  --gateway-port <n>     listen port                      (default 8080)
  --gateway-host <addr>  bind address                     (default 0.0.0.0)
  --gateway-rate <n>     requests per minute per client   (default 60)
  --gateway-trust-proxy <n>  how many reverse proxies sit in front (default 0).
                         Set it if you run nginx/Caddy for TLS — otherwise every
                         client shares one bucket and the faucet serves one
                         person per cooldown. Leave it 0 if you do not, or
                         anyone can forge their address with a header.

Faucet — refuses to run on mainnet.

  --faucet               enable it
  --faucet-wallet <path> mnemonic file, created if absent (default <datadir>/faucet.key)
  --faucet-amount <n>    DECKX per grant                  (default 10)
  --faucet-reserve <n>   DECKX kept back                  (default 100)
  --faucet-daily-cap <n> DECKX per rolling 24 hours       (default 5000)
  --faucet-cooldown <m>  minutes between grants per address (default 60)

Example — a public seed node with a gateway and a faucet:

  node src/deckxd.ts --network testnet --datadir /var/lib/deckxd \\
       --host 0.0.0.0 --port 19333 \\
       --gateway --gateway-port 8080 \\
       --faucet --faucet-amount 10 --mine dxc1q...

Example — a two-node local testnet:

  node src/deckxd.ts --network regtest --datadir ./data/a --port 29001 --rpcport 29101 \\
       --mine dxc1q...
  node src/deckxd.ts --network regtest --datadir ./data/b --port 29002 --rpcport 29102 \\
       --connect 127.0.0.1:29001
`;

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(red(`deckxd: ${(err as Error).message}`));
    process.exit(1);
  },
);
