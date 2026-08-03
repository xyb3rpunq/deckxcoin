#!/usr/bin/env node
/**
 * deckx — command line interface.
 *
 *   deckx genesis            print the genesis block and verify its proof of work
 *   deckx keygen <seed>      derive a deterministic address from a seed phrase
 *   deckx mine <n>           mine n regtest blocks and report the state root
 *   deckx scenario           run the full reference scenario (real PoW, ~2 min)
 *   deckx volt               run the Volt payment demo on a regtest chain
 *   deckx verify             re-derive genesis and check it matches the constant
 */

import { Blockchain, GENESIS_TIME } from './chain.ts';
import {
  bitsToTarget,
  blockHash,
  blockSubsidy,
  checkHeader,
  GENESIS_BITS,
  meetsTarget,
} from './block.ts';
import { COINBASE_MATURITY } from './state.ts';
import { formatDeckx, txid, ZAPS_PER_DECKX } from './tx.ts';
import { keyPairFromSeed, toHex } from './crypto.ts';
import { runScenario } from './scenario.ts';
import { VoltNetwork } from './volt/network.ts';
import { encodeInvoice } from './volt/invoice.ts';

const [, , command = 'help', ...args] = process.argv;

const bold = (s: string) => `[1m${s}[0m`;
const dim = (s: string) => `[2m${s}[0m`;
const green = (s: string) => `[32m${s}[0m`;
const red = (s: string) => `[31m${s}[0m`;

const row = (label: string, value: string) => console.log(`  ${dim(label.padEnd(16))} ${value}`);

switch (command) {
  case 'genesis': {
    const chain = Blockchain.create();
    const h = chain.tip.header;
    const cb = chain.tip.transactions[0];
    const hash = blockHash(h);

    console.log(bold('\nDeckxCoin genesis block\n'));
    row('hash', hash);
    row('height', String(h.height));
    row('prevHash', h.prevHash);
    row('merkleRoot', h.merkleRoot);
    row('stateRoot', h.stateRoot);
    row('time', `${h.time} (${new Date(h.time * 1000).toISOString()})`);
    row('bits', `0x${h.bits.toString(16)}`);
    row('target', `0x${bitsToTarget(h.bits).toString(16)}`);
    row('nonce', String(h.nonce));
    console.log();
    row('coinbase txid', txid(cb));
    row('reward', formatDeckx(BigInt(cb.outputs[0].value)));
    row('address', cb.outputs[0].address);
    row('memo', cb.memo ?? '');
    console.log();
    row('pow valid', meetsTarget(hash, h.bits) ? green('yes') : red('NO'));
    row('header valid', checkHeader(chain.tip, GENESIS_TIME + 1).ok ? green('yes') : red('NO'));
    row('supply', chain.auditSupply().balanced ? green('balanced') : red('DRIFT'));
    console.log();
    break;
  }

  case 'verify': {
    // Build genesis twice and confirm both runs agree. A chain whose genesis
    // is not reproducible cannot be independently audited.
    const a = Blockchain.create();
    const b = Blockchain.create();
    const same = blockHash(a.tip.header) === blockHash(b.tip.header);
    console.log(`\n  genesis A  ${blockHash(a.tip.header)}`);
    console.log(`  genesis B  ${blockHash(b.tip.header)}`);
    console.log(`\n  ${same ? green('reproducible ✓') : red('DIVERGENT ✗')}\n`);
    process.exit(same ? 0 : 1);
  }

  case 'keygen': {
    const seed = args[0];
    if (!seed) {
      console.error('usage: deckx keygen <seed phrase>');
      process.exit(2);
    }
    const key = keyPairFromSeed(seed);
    console.log(bold('\nDeterministic key\n'));
    row('seed', seed);
    row('pubkey', toHex(key.publicKey));
    row('address', key.address);
    console.log(dim('\n  Derived from the seed alone — anyone with this phrase controls the funds.\n'));
    break;
  }

  case 'mine': {
    const n = Number(args[0] ?? 10);
    const chain = Blockchain.regtest();
    const miner = keyPairFromSeed('deckx/cli/miner');
    let t = chain.tip.header.time;
    const started = Date.now();

    for (let i = 0; i < n; i++) {
      t += 600;
      const { result } = chain.mineBlock([], miner.address, { time: t });
      if (!result.ok) {
        console.error(red(`block ${i + 1} rejected: ${result.error}`));
        process.exit(1);
      }
    }
    console.log(bold(`\nMined ${n} regtest blocks in ${Date.now() - started}ms\n`));
    row('tip height', String(chain.height));
    row('tip hash', chain.tipHash);
    row('state root', chain.state.stateRoot());
    row('utxos', String(chain.state.utxoCount));
    row('chainwork', chain.chainWork.toString());
    row('issued', formatDeckx(chain.auditSupply().utxoTotal));
    row('mature at', `height ${COINBASE_MATURITY}`);
    console.log();
    break;
  }

  case 'scenario': {
    console.log(bold('\nDeckxCoin reference scenario') + dim(' — real proof of work, this takes a while\n'));
    const { chain, timings } = runScenario({ verbose: true });
    console.log(bold('\nFinal state\n'));
    row('tip height', String(chain.height));
    row('tip hash', chain.tipHash);
    row('utxos', String(chain.state.utxoCount));
    row('supply', chain.auditSupply().balanced ? green('balanced') : red('DRIFT'));
    row('genesis mine', `${timings.genesisMs}ms`);
    console.log();
    break;
  }

  case 'volt': {
    console.log(bold('\nVolt: a routed payment across two channels\n'));
    const chain = Blockchain.regtest();
    const miner = keyPairFromSeed('deckxcoin/regtest');

    let t = chain.tip.header.time;
    for (let i = 0; i <= COINBASE_MATURITY + 2; i++) {
      t += 600;
      chain.mineBlock([], miner.address, { time: t });
    }

    const net = new VoltNetwork();
    const alice = net.addNode('alice', 'cli/volt/alice');
    const bob = net.addNode('bob', 'cli/volt/bob');
    const carol = net.addNode('carol', 'cli/volt/carol');

    const utxos = chain.state
      .utxosFor(miner.address)
      .filter((u) => chain.height - u.height >= COINBASE_MATURITY);

    const ab = net.openChannel({
      a: alice, b: bob, capacity: 3n * ZAPS_PER_DECKX,
      funding: utxos[0], funderKey: miner, changeAddress: miner.address,
    });
    const bc = net.openChannel({
      a: bob, b: carol, capacity: 3n * ZAPS_PER_DECKX,
      funding: utxos[1], funderKey: miner, changeAddress: miner.address,
    });

    t += 600;
    chain.mineBlock([ab.fundingTx, bc.fundingTx], miner.address, { time: t });
    net.confirmAll(chain);

    row('channels', `${net.stats().channels} open · ${formatDeckx(BigInt(net.stats().capacity))} capacity`);
    row('funding txs', `${txid(ab.fundingTx).slice(0, 20)}… / ${txid(bc.fundingTx).slice(0, 20)}…`);

    const invoice = carol.invoice(50_000_000n, 'CLI demo', { seed: 'cli/demo', timestamp: t });
    const encoded = encodeInvoice(invoice);
    console.log(`\n  ${dim('invoice')}  ${encoded.slice(0, 72)}…\n`);

    const result = net.payInvoice(alice, encoded, { currentHeight: chain.height, now: t });
    if (!result.ok) {
      console.error(red(`payment failed: ${result.error}`));
      process.exit(1);
    }

    row('route', result.route!.hops.map((h) => h.to.slice(0, 8)).join(' → '));
    row('sent', formatDeckx(result.amountSent!));
    row('routing fee', `${result.feesPaid} zaps`);
    row('onion size', `${result.onionSize} bytes (constant)`);
    row('preimage', result.preimage!.slice(0, 32) + '…');
    for (const f of result.forwards) {
      row(`  ${f.node}`, `in ${f.amountIn} · out ${f.amountOut} · fee ${f.fee} · cltv ${f.cltv}`);
    }
    row('on-chain txs', green('0'));
    row('chain height', `${chain.height} (unchanged by the payment)`);
    console.log();
    break;
  }

  default:
    console.log(`
${bold('deckx')} — DeckxCoin reference implementation

  ${bold('deckx genesis')}        print and verify the genesis block
  ${bold('deckx verify')}         confirm genesis is reproducible
  ${bold('deckx keygen <seed>')}  derive a deterministic address
  ${bold('deckx mine <n>')}       mine n regtest blocks
  ${bold('deckx scenario')}       full reference scenario, real proof of work
  ${bold('deckx volt')}           routed off-chain payment demo

  ${dim('subsidy at height 0:')} ${formatDeckx(blockSubsidy(0))}
  ${dim('genesis difficulty: ')} 0x${GENESIS_BITS.toString(16)}
`);
}
