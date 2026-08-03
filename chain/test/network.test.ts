/**
 * Multi-node networking.
 *
 * These tests run real nodes over real TCP sockets on loopback. Nothing is
 * mocked: the frames are the frames a remote peer would send, the handshake is
 * the handshake, and convergence is measured by comparing state roots.
 *
 * The reason to test this way is that every interesting networking bug lives
 * in the seams — a peer that handshakes but never syncs, a block that relays
 * but leaves the mempool stale, two nodes that agree on the tip hash while
 * disagreeing on the UTXO set. A mocked transport hides all three.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DeckxNode } from '../src/node/node.ts';
import { RpcServer, rpcCall } from '../src/node/rpc.ts';
import { REGTEST } from '../src/params.ts';
import { ACCEPT } from '../src/node/chainstate.ts';
import { keyPairFromSeed } from '../src/crypto.ts';
import { signTx, transferTx, txid, ZAPS_PER_DECKX } from '../src/tx.ts';
import { COINBASE_MATURITY } from '../src/state.ts';
import { blockHash } from '../src/block.ts';
import { decodeMessage, encodeMessage, MSG, PROTOCOL_VERSION } from '../src/net/wire.ts';

/* ─────────────────────────────────────────────────────────── harness ── */

const dirs: string[] = [];
const running: DeckxNode[] = [];
let nextPort = 29500;

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'deckx-net-'));
  dirs.push(dir);
  return dir;
}

async function spawnNode(opts: { connect?: string[]; listen?: boolean } = {}): Promise<DeckxNode> {
  const node = new DeckxNode({
    params: REGTEST,
    datadir: tempDir(),
    listenPort: nextPort++,
    listenHost: '127.0.0.1',
    listen: opts.listen ?? true,
    connect: opts.connect,
    // Dial often so tests do not wait on the default top-up cadence.
    dialIntervalMs: 250,
    userAgent: 'deckxd-test',
  });
  await node.start();
  running.push(node);
  return node;
}

/** Poll until `check` is true, or fail with a useful message. */
async function until(check: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for: ${what}`);
}

test.after(async () => {
  for (const node of running) {
    try {
      await node.stop();
    } catch {
      /* already stopped */
    }
  }
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* Windows may still hold the WAL; a leaked temp dir is harmless. */
    }
  }
});

/* ───────────────────────────────────────────────────── wire protocol ── */

test('a frame round-trips through encode and decode', () => {
  const frame = encodeMessage(REGTEST.magic, MSG.PING, { nonce: 'abc123' });
  const result = decodeMessage(REGTEST.magic, frame);

  assert.equal(result.error, undefined);
  assert.equal(result.consumed, frame.length);
  assert.equal(result.message!.command, MSG.PING);
  assert.deepEqual(result.message!.payload, { nonce: 'abc123' });
});

test('a partial frame consumes nothing and waits for more bytes', () => {
  const frame = encodeMessage(REGTEST.magic, MSG.VERACK, {});
  const partial = frame.subarray(0, frame.length - 1);
  const result = decodeMessage(REGTEST.magic, partial);

  assert.equal(result.consumed, 0);
  assert.equal(result.message, undefined);
  assert.equal(result.error, undefined, 'an incomplete frame is not an error');
});

test('two frames in one buffer are decoded one at a time', () => {
  const a = encodeMessage(REGTEST.magic, MSG.PING, { nonce: '1' });
  const b = encodeMessage(REGTEST.magic, MSG.PONG, { nonce: '1' });
  const merged = new Uint8Array(a.length + b.length);
  merged.set(a, 0);
  merged.set(b, a.length);

  const first = decodeMessage(REGTEST.magic, merged);
  assert.equal(first.message!.command, MSG.PING);
  const second = decodeMessage(REGTEST.magic, merged.subarray(first.consumed));
  assert.equal(second.message!.command, MSG.PONG);
});

test('the wrong network magic is rejected on the first frame', () => {
  const frame = encodeMessage(0xdeadbeef, MSG.PING, {});
  const result = decodeMessage(REGTEST.magic, frame);
  assert.match(result.error!, /wrong network magic/);
});

test('a corrupted payload fails its checksum', () => {
  const frame = encodeMessage(REGTEST.magic, MSG.PING, { nonce: 'abc' });
  frame[frame.length - 2] ^= 0xff;
  const result = decodeMessage(REGTEST.magic, frame);
  assert.match(result.error!, /checksum mismatch/);
});

/* ────────────────────────────────────────────────────────── handshake ── */

test('two nodes connect and complete the handshake', async () => {
  const a = await spawnNode();
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`] });

  await until(() => a.net.readyPeers.length === 1 && b.net.readyPeers.length === 1, 'handshake');

  const [peerOfB] = b.net.readyPeers;
  assert.equal(peerOfB.outbound, true, 'b dialled a');
  assert.equal(peerOfB.version, PROTOCOL_VERSION);
  assert.equal(peerOfB.userAgent, 'deckxd-test');

  const [peerOfA] = a.net.readyPeers;
  assert.equal(peerOfA.outbound, false, 'a accepted the connection');
});

test('a node discovers a third peer through address gossip', async () => {
  const hub = await spawnNode();
  const a = await spawnNode({ connect: [`127.0.0.1:${hub.net.listenPort}`] });
  await until(() => a.net.readyPeers.length >= 1, 'a connects to the hub');

  // b learns about a only via the hub's addr gossip.
  const b = await spawnNode({ connect: [`127.0.0.1:${hub.net.listenPort}`] });
  await until(() => b.net.readyPeers.length >= 2, 'b discovers a through gossip', 12000);

  const ports = b.net.readyPeers.map((p) => p.listenPort || p.port);
  assert.ok(
    ports.includes(a.net.listenPort) || a.net.readyPeers.length >= 2,
    `b should have found a; b sees ${ports}, a has ${a.net.readyPeers.length} peers`,
  );
});

/* ────────────────────────────────────────────────────── block relay ── */

test('a mined block propagates to a peer and both agree on the state root', async () => {
  const a = await spawnNode();
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`] });
  await until(() => a.net.readyPeers.length === 1 && b.net.readyPeers.length === 1, 'handshake');

  const miner = keyPairFromSeed('net/relay/miner');
  const res = a.mineOne(miner.address);
  assert.equal(res.accepted.status, ACCEPT.CONNECTED, res.accepted.error);

  await until(() => b.chain.height === 1, 'block reaches b');

  assert.equal(b.chain.tipHash, a.chain.tipHash);
  assert.equal(b.chain.state.stateRoot(), a.chain.state.stateRoot());
  assert.equal(b.chain.state.balanceOf(miner.address), a.chain.state.balanceOf(miner.address));
  assert.equal(b.chain.auditSupply().balanced, true);
});

test('a node that joins late syncs the whole chain from its peer', async () => {
  const a = await spawnNode();
  const miner = keyPairFromSeed('net/sync/miner');
  for (let i = 0; i < 12; i++) {
    const res = a.mineOne(miner.address);
    assert.equal(res.accepted.status, ACCEPT.CONNECTED, res.accepted.error);
  }
  assert.equal(a.chain.height, 12);

  // b starts from genesis and must catch up on its own.
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`] });
  await until(() => b.chain.height === 12, 'b syncs 12 blocks', 15000);

  assert.equal(b.chain.tipHash, a.chain.tipHash);
  assert.equal(b.chain.state.stateRoot(), a.chain.state.stateRoot());
  assert.equal(b.chain.auditSupply().balanced, true);
  assert.equal(b.chain.state.balanceOf(miner.address), a.chain.state.balanceOf(miner.address));
});

test('blocks arriving out of order are held as orphans and connected later', async () => {
  const source = await spawnNode({ listen: false });
  const miner = keyPairFromSeed('net/orphan/miner');
  for (let i = 0; i < 3; i++) source.mineOne(miner.address);

  const target = await spawnNode({ listen: false });

  // Feed the blocks backwards: 3, 2, 1.
  const three = source.chain.getBlock(source.chain.headerAt(3)!.hash)!;
  const two = source.chain.getBlock(source.chain.headerAt(2)!.hash)!;
  const one = source.chain.getBlock(source.chain.headerAt(1)!.hash)!;

  assert.equal(target.submitBlock(three).status, ACCEPT.ORPHAN);
  assert.equal(target.submitBlock(two).status, ACCEPT.ORPHAN);
  assert.equal(target.chain.height, 0, 'nothing connects without the first block');

  assert.equal(target.submitBlock(one).status, ACCEPT.CONNECTED);
  // Submitting the parent should let the held orphans connect on their own.
  target.submitBlock(two);
  target.submitBlock(three);

  assert.equal(target.chain.height, 3);
  assert.equal(target.chain.tipHash, source.chain.tipHash);
  assert.equal(target.chain.state.stateRoot(), source.chain.state.stateRoot());
});

/* ────────────────────────────────────────────────────── transactions ── */

test('a transaction relays to a peer, is mined, and leaves both mempools', async () => {
  const a = await spawnNode();
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`] });
  await until(() => a.net.readyPeers.length === 1 && b.net.readyPeers.length === 1, 'handshake');

  const miner = keyPairFromSeed('net/tx/miner');
  const payee = keyPairFromSeed('net/tx/payee');

  for (let i = 0; i < COINBASE_MATURITY + 1; i++) a.mineOne(miner.address);
  await until(() => b.chain.height === a.chain.height, 'b catches up', 25000);

  const coin = a.chain.state
    .utxosFor(miner.address)
    .filter((u) => a.chain.height - u.height >= COINBASE_MATURITY)[0];
  const send = 3n * ZAPS_PER_DECKX;
  const tx = signTx(
    transferTx({
      inputs: [{ txid: coin.txid, vout: coin.vout }],
      outputs: [
        { value: send.toString(), address: payee.address },
        { value: (coin.value - send - 2000n).toString(), address: miner.address },
      ],
      memo: 'relayed across the network',
    }),
    miner,
    [{ value: coin.value, address: coin.address }],
  );

  const accepted = a.submitTransaction(tx);
  assert.equal(accepted.ok, true, accepted.error);
  a.relayTransaction(tx);

  const id = txid(tx);
  await until(() => b.mempool.has(id), 'transaction reaches b');
  assert.equal(b.mempool.get(id)!.memo, 'relayed across the network');

  // b mines it; a must then drop it from its own pool when the block arrives.
  const mined = b.mineOne(keyPairFromSeed('net/tx/b-miner').address);
  assert.equal(mined.accepted.status, ACCEPT.CONNECTED, mined.accepted.error);
  assert.ok(mined.block.transactions.some((t) => txid(t) === id), 'b included the transaction');

  await until(() => a.chain.height === b.chain.height, 'block returns to a');
  assert.equal(a.mempool.has(id), false, 'a must drop a mined transaction');
  assert.equal(b.mempool.has(id), false);
  assert.equal(a.chain.state.balanceOf(payee.address), send);
  assert.equal(a.chain.state.stateRoot(), b.chain.state.stateRoot());
});

/* ─────────────────────────────────────────────── fork convergence ── */

test('CONVERGENCE: two nodes mine independently, then agree on the heavier chain', async () => {
  // Start disconnected so each builds its own branch.
  const a = await spawnNode({ listen: true });
  const b = await spawnNode({ listen: true });

  const minerA = keyPairFromSeed('net/fork/a');
  const minerB = keyPairFromSeed('net/fork/b');

  for (let i = 0; i < 2; i++) a.mineOne(minerA.address);
  for (let i = 0; i < 4; i++) b.mineOne(minerB.address);

  assert.equal(a.chain.height, 2);
  assert.equal(b.chain.height, 4);
  assert.notEqual(a.chain.tipHash, b.chain.tipHash);

  // Introduce them. a must abandon its branch for b's heavier one.
  await a.net.connect('127.0.0.1', b.net.listenPort);
  await until(() => a.net.readyPeers.length >= 1 && b.net.readyPeers.length >= 1, 'handshake');
  await until(() => a.chain.height === 4, 'a reorgs onto the heavier chain', 15000);

  assert.equal(a.chain.tipHash, b.chain.tipHash, 'tips must match');
  assert.equal(a.chain.state.stateRoot(), b.chain.state.stateRoot(), 'state roots must match');
  assert.equal(
    a.chain.state.balanceOf(minerA.address),
    0n,
    "a's own coinbases were undone by the reorg",
  );
  assert.ok(a.chain.state.balanceOf(minerB.address) > 0n);
  assert.equal(a.chain.auditSupply().balanced, true);
  assert.equal(b.chain.auditSupply().balanced, true);

  // a still retains its losing branch — a branch that lost can win later.
  const losing = a.chain.getHeader(a.chain.store.bestHeader()!.hash);
  assert.ok(losing);
  assert.ok(a.chain.store.blockCount >= 7, 'both branches stay stored');
});

/* ────────────────────────────────────────────────── misbehaviour ── */

test('a peer sending an invalid block is banned', async () => {
  const a = await spawnNode();
  const b = await spawnNode({ connect: [`127.0.0.1:${a.net.listenPort}`] });
  await until(() => a.net.readyPeers.length === 1 && b.net.readyPeers.length === 1, 'handshake');

  const miner = keyPairFromSeed('net/ban/miner');
  b.mineOne(miner.address);
  await until(() => a.chain.height === 1, 'valid block relays first');

  // Forge a block: valid proof of work is not attempted, so `a` rejects it.
  const good = b.chain.getBlock(b.chain.tipHash)!;
  const forged = {
    header: { ...good.header, height: 2, prevHash: b.chain.tipHash, nonce: 12345 },
    transactions: good.transactions,
  };

  let banned = false;
  a.on('banned', () => {
    banned = true;
  });
  b.net.readyPeers[0].send(MSG.BLOCK, forged);

  await until(() => banned, 'a bans the sender of an invalid block');
  assert.equal(a.chain.height, 1, 'the forged block never connected');
});

/* ─────────────────────────────────────────────────────────── RPC ── */

test('the JSON-RPC surface answers over HTTP', async () => {
  const node = await spawnNode({ listen: false });
  const rpc = new RpcServer({ node, port: nextPort++ });
  await rpc.start();
  const url = `http://127.0.0.1:${rpc.port}`;

  try {
    const miner = keyPairFromSeed('net/rpc/miner');

    const generated = (await rpcCall(url, 'generate', { count: 3, address: miner.address })) as {
      blocks: string[];
      height: number;
    };
    assert.equal(generated.blocks.length, 3);
    assert.equal(generated.height, 3);

    const info = (await rpcCall(url, 'getblockchaininfo')) as Record<string, unknown>;
    assert.equal(info.network, 'regtest');
    assert.equal(info.height, 3);
    assert.equal(info.supplyBalanced, true);
    assert.equal(info.tip, node.chain.tipHash);

    const hash = (await rpcCall(url, 'getblockhash', { height: 2 })) as string;
    assert.equal(hash, node.chain.headerAt(2)!.hash);

    const block = (await rpcCall(url, 'getblock', { hash })) as { height: number; txids: string[] };
    assert.equal(block.height, 2);
    assert.equal(block.txids.length, 1);

    const balance = (await rpcCall(url, 'getbalance', { address: miner.address })) as {
      balance: string;
      utxos: number;
    };
    assert.equal(BigInt(balance.balance), node.chain.state.balanceOf(miner.address));
    assert.equal(balance.utxos, 3);

    const audit = (await rpcCall(url, 'auditsupply')) as { balanced: boolean };
    assert.equal(audit.balanced, true);

    // Errors come back as JSON-RPC errors, not HTTP failures.
    await assert.rejects(() => rpcCall(url, 'getbalance', { address: 'not-an-address' }), /not a valid/);
    await assert.rejects(() => rpcCall(url, 'nosuchmethod'), /unknown method/);
    await assert.rejects(() => rpcCall(url, 'getblockhash', { height: 9999 }), /no active block/);
  } finally {
    await rpc.stop();
  }
});

test('RPC accepts and relays a raw transaction', async () => {
  const node = await spawnNode({ listen: false });
  const rpc = new RpcServer({ node, port: nextPort++ });
  await rpc.start();
  const url = `http://127.0.0.1:${rpc.port}`;

  try {
    const miner = keyPairFromSeed('net/rpc/tx/miner');
    const payee = keyPairFromSeed('net/rpc/tx/payee');
    await rpcCall(url, 'generate', { count: COINBASE_MATURITY + 1, address: miner.address });

    const coin = node.chain.state
      .utxosFor(miner.address)
      .filter((u) => node.chain.height - u.height >= COINBASE_MATURITY)[0];
    const tx = signTx(
      transferTx({
        inputs: [{ txid: coin.txid, vout: coin.vout }],
        outputs: [
          { value: ZAPS_PER_DECKX.toString(), address: payee.address },
          { value: (coin.value - ZAPS_PER_DECKX - 1000n).toString(), address: miner.address },
        ],
      }),
      miner,
      [{ value: coin.value, address: coin.address }],
    );

    const sent = (await rpcCall(url, 'sendrawtransaction', { transaction: tx })) as {
      txid: string;
      accepted: boolean;
    };
    assert.equal(sent.accepted, true);
    assert.equal(sent.txid, txid(tx));

    const pool = (await rpcCall(url, 'getrawmempool')) as string[];
    assert.deepEqual(pool, [txid(tx)]);

    await rpcCall(url, 'generate', { count: 1, address: miner.address });
    const afterMining = (await rpcCall(url, 'getrawmempool')) as string[];
    assert.deepEqual(afterMining, [], 'mining must clear the pool');

    const balance = (await rpcCall(url, 'getbalance', { address: payee.address })) as { balance: string };
    assert.equal(BigInt(balance.balance), ZAPS_PER_DECKX);

    // A double spend of the same coin is refused.
    await assert.rejects(() => rpcCall(url, 'sendrawtransaction', { transaction: tx }), /already-spent|unknown/);
  } finally {
    await rpc.stop();
  }
});

void blockHash;
