#!/usr/bin/env node
/**
 * Launch a local multi-node testnet in one process.
 *
 *   node scripts/testnet.ts               # 3 nodes, regtest, 10s blocks
 *   node scripts/testnet.ts --nodes 5 --network testnet --interval 30
 *
 * Each node gets its own datadir, its own P2P port, its own RPC port, and its
 * own miner address. Node 1 mines; the rest sync. Run it, then poke the nodes
 * with curl while it is up:
 *
 *   curl -s localhost:29101 -d '{"method":"getblockchaininfo"}' | jq
 *   curl -s localhost:29102 -d '{"method":"getpeerinfo"}' | jq
 *
 * Why in one process: it is far easier to reason about than a shell script
 * juggling background PIDs, and it is the same `DeckxNode` a standalone
 * `deckxd` runs — the sockets between them are real TCP either way.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { DeckxNode } from '../src/node/node.ts';
import { RpcServer } from '../src/node/rpc.ts';
import { networkByName } from '../src/params.ts';
import { keyPairFromSeed } from '../src/crypto.ts';
import { formatDeckx } from '../src/tx.ts';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i++) {
  const token = process.argv[i];
  if (token.startsWith('--')) args.set(token.slice(2), process.argv[i + 1] ?? '');
}

const nodeCount = Math.max(2, Math.min(Number(args.get('nodes') ?? 3), 8));
const params = networkByName(args.get('network') ?? 'regtest');
const intervalMs = Math.max(1, Number(args.get('interval') ?? 10)) * 1000;
const baseP2P = Number(args.get('p2p-base') ?? 29001);
const baseRpc = Number(args.get('rpc-base') ?? 29101);
const datadirRoot = args.get('datadir') ? resolve(args.get('datadir')!) : mkdtempSync(join(tmpdir(), 'deckx-testnet-'));

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const stamp = () => dim(new Date().toISOString().slice(11, 19));

interface Running {
  readonly name: string;
  readonly node: DeckxNode;
  readonly rpc: RpcServer;
  readonly address: string;
  readonly p2pPort: number;
  readonly rpcPort: number;
}

const running: Running[] = [];

async function main(): Promise<void> {
  console.log(bold(`\nDeckxCoin local testnet — ${nodeCount} nodes on ${params.name}\n`));
  console.log(dim(`  datadir root  ${datadirRoot}`));
  console.log(dim(`  block interval ${intervalMs / 1000}s\n`));

  for (let i = 0; i < nodeCount; i++) {
    const name = `node${i + 1}`;
    const p2pPort = baseP2P + i;
    const rpcPort = baseRpc + i;

    // Every node dials the one before it, forming a chain of connections that
    // address gossip then fills into a mesh.
    const connect = i === 0 ? [] : [`127.0.0.1:${baseP2P + i - 1}`];

    const node = new DeckxNode({
      params,
      datadir: join(datadirRoot, name),
      listenPort: p2pPort,
      listenHost: '127.0.0.1',
      connect,
      dialIntervalMs: 2000,
      userAgent: `deckxd-testnet/${name}`,
    });

    const rpc = new RpcServer({ node, port: rpcPort });
    const address = keyPairFromSeed(`testnet/${name}`).address;

    node.on('tip', (tip: { height: number; hash: string }) => {
      console.log(`${stamp()} ${bold(name)} tip ${tip.height} ${dim(tip.hash.slice(0, 16) + '…')}`);
    });
    node.on('reorg', (r: { disconnected: string[]; connected: string[] }) => {
      console.log(`${stamp()} ${bold(name)} ${green('reorg')} -${r.disconnected.length} +${r.connected.length}`);
    });
    node.on('peerReady', (p: { id: string }) => {
      console.log(`${stamp()} ${bold(name)} peer ${p.id}`);
    });

    await node.start();
    await rpc.start();
    running.push({ name, node, rpc, address, p2pPort, rpcPort });

    console.log(
      `  ${bold(name.padEnd(6))} p2p ${dim(`127.0.0.1:${p2pPort}`)}  rpc ${dim(`http://127.0.0.1:${rpcPort}`)}  ${dim(address)}`,
    );
  }

  console.log(`\n${dim('genesis')} ${running[0].node.chain.headerAt(0)!.hash}\n`);

  // node1 mines; everyone else should follow purely through the network.
  const miner = running[0];
  const timer = setInterval(() => {
    try {
      const res = miner.node.mineOne(miner.address);
      if (res.accepted.status !== 'connected') {
        console.error(`${stamp()} ${miner.name} mine rejected: ${res.accepted.error}`);
      }
    } catch (err) {
      console.error(`${stamp()} ${miner.name} mine error: ${(err as Error).message}`);
    }
  }, intervalMs);

  // Periodic convergence check — the number that actually matters.
  const status = setInterval(() => {
    const heights = running.map((r) => r.node.chain.height);
    const roots = new Set(running.map((r) => r.node.chain.state.stateRoot()));
    const converged = roots.size === 1;
    console.log(
      `${stamp()} ${dim('network')}  heights=[${heights.join(', ')}] ` +
        `${converged ? green('converged') : `\x1b[33mdiverged (${roots.size} state roots)\x1b[0m`} ` +
        dim(`supply=${formatDeckx(running[0].node.chain.auditSupply().utxoTotal)}`),
    );
  }, Math.max(intervalMs, 15_000));

  console.log(dim('Mining. Ctrl-C to stop.\n'));

  const shutdown = async () => {
    clearInterval(timer);
    clearInterval(status);
    console.log(`\n${dim('shutting down')}`);
    for (const r of running) {
      await r.rpc.stop();
      await r.node.stop();
    }
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  await new Promise(() => {});
}

main().catch((err) => {
  console.error(`testnet: ${(err as Error).message}`);
  process.exit(1);
});
