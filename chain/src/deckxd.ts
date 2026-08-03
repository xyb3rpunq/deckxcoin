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

import { resolve } from 'node:path';

import { DeckxNode } from './node/node.ts';
import { RpcServer } from './node/rpc.ts';
import { networkByName } from './params.ts';
import { isValidAddress } from './crypto.ts';
import { formatDeckx } from './tx.ts';

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

  const mineTo = args.one('mine');
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

  console.log(bold(`\ndeckxd — ${params.name}\n`));
  const row = (k: string, v: string) => console.log(`  ${dim(k.padEnd(12))} ${v}`);
  row('datadir', datadir);
  row('p2p', `${args.one('host', '127.0.0.1')}:${port}`);
  row('rpc', `http://127.0.0.1:${rpcPort}`);
  row('genesis', node.chain.headerAt(0)!.hash);
  row('height', String(node.chain.height));
  row('supply', formatDeckx(node.chain.auditSupply().utxoTotal));
  if (mineTo) row('mining to', mineTo);
  console.log();

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

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${stamp()} ${dim(signal)} — closing`);
    if (miner) clearInterval(miner);
    if (status) clearInterval(status);
    await rpc.stop();
    await node.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  // Hold the process open; every timer above is unref'd on purpose so that
  // this interval is the single thing keeping the node alive.
  await new Promise(() => {});
  return 0;
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
