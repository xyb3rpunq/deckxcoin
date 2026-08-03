/**
 * Generate the JSON the website's explorer reads.
 *
 * Run manually — it mines 100+ real proof-of-work blocks and takes a couple of
 * minutes. The output is committed, so the site is a static file and the
 * numbers on it are reproducible: re-run this and you get the same genesis
 * hash, the same txids, the same routing fees.
 *
 *   node scripts/export-web-data.ts
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runScenario } from '../src/scenario.ts';
import {
  bitsToTarget,
  blockHash,
  blockSubsidy,
  cumulativeIssuance,
  GENESIS_BITS,
  HALVING_INTERVAL,
  INITIAL_SUBSIDY,
  MAX_SUPPLY,
  TARGET_SPACING,
  terminalHeight,
} from '../src/block.ts';
import { CONTRACT_SPECS } from '../src/contracts/index.ts';
import { txid, wtxid, formatDeckx, type Transaction } from '../src/tx.ts';
import { toHex } from '../src/crypto.ts';
import { CHANNEL_STATE } from '../src/volt/channel.ts';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '../../web/data/chain.json');

function summariseTx(tx: Transaction, height: number) {
  return {
    txid: txid(tx),
    wtxid: wtxid(tx),
    kind: tx.kind,
    height,
    inputs: tx.inputs.map((i) => ({
      outpoint: `${i.txid.slice(0, 16)}…:${i.vout}`,
      sequence: i.sequence,
      hasCosign: Boolean(i.cosign),
      hasPreimage: Boolean(i.preimage),
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value,
      pretty: formatDeckx(BigInt(o.value)),
      address: o.address,
      script: o.script?.type ?? 'p2pkh',
    })),
    memo: tx.memo ?? null,
    contract: tx.contract
      ? {
          target: tx.contract.target ?? null,
          codeSize: tx.contract.code ? tx.contract.code.length / 2 : 0,
          gasLimit: tx.contract.gasLimit,
          gasPrice: tx.contract.gasPrice,
          nonce: tx.contract.nonce,
        }
      : null,
  };
}

console.log('Running the reference scenario — this mines real proof of work…');
const started = Date.now();
const { chain, net, log, contract, payment, timings } = runScenario({ verbose: true });

const genesis = chain.blocks[0];
const contractAccount = chain.state.getContract(contract);

const blocks = chain.blocks.map((b) => ({
  height: b.header.height,
  hash: blockHash(b.header),
  prevHash: b.header.prevHash,
  merkleRoot: b.header.merkleRoot,
  stateRoot: b.header.stateRoot,
  time: b.header.time,
  bits: `0x${(b.header.bits >>> 0).toString(16)}`,
  nonce: b.header.nonce,
  txCount: b.transactions.length,
  subsidy: blockSubsidy(b.header.height).toString(),
  transactions: b.transactions.map((t) => summariseTx(t, b.header.height)),
}));

/** Only the blocks that carry something other than a lone coinbase. */
const notableHeights = new Set(
  blocks.filter((b) => b.txCount > 1).map((b) => b.height),
);
notableHeights.add(0);

const channels = [...net.channels.entries()].map(([scid, ch]) => ({
  shortChannelId: scid.toString(),
  id: ch.id,
  state: ch.state,
  capacity: ch.capacity.toString(),
  capacityPretty: formatDeckx(ch.capacity),
  balanceA: ch.balanceA.toString(),
  balanceB: ch.balanceB.toString(),
  commitmentNumber: ch.commitmentNumber,
  revocations: ch.revokedByA.size,
  htlcsSettled: ch.htlcs.filter((h) => h.status === 'settled').length,
  fundingTxid: ch.funding.txid,
  parties: [ch.a.name, ch.b.name],
}));

const data = {
  generatedAt: new Date().toISOString(),
  generatorVersion: '0.1.0',
  network: {
    name: 'DeckxCoin mainnet-alpha',
    ticker: 'DECKX',
    unit: 'zap',
    unitsPerCoin: '100000000',
    targetSpacingSeconds: TARGET_SPACING,
    coinbaseMaturity: 100,
  },
  monetary: {
    maxSupply: MAX_SUPPLY.toString(),
    maxSupplyPretty: formatDeckx(MAX_SUPPLY),
    halvingIntervalBlocks: HALVING_INTERVAL,
    halvingIntervalDays: (HALVING_INTERVAL * TARGET_SPACING) / 86_400,
    initialSubsidy: INITIAL_SUBSIDY.toString(),
    initialSubsidyPretty: formatDeckx(INITIAL_SUBSIDY),
    terminalHeight: terminalHeight(),
    terminalYears: Math.round((terminalHeight() + 1) / HALVING_INTERVAL),
    // The full issuance curve, one point per halving era.
    schedule: Array.from({ length: 36 }, (_, era) => {
      const height = era * HALVING_INTERVAL;
      const subsidy = blockSubsidy(height);
      const issued = cumulativeIssuance(height + HALVING_INTERVAL - 1);
      return {
        era,
        year: era + 1,
        startHeight: height,
        subsidy: subsidy.toString(),
        subsidyPretty: formatDeckx(subsidy),
        cumulative: issued.toString(),
        cumulativePretty: formatDeckx(issued),
        percentOfCap: ((Number(issued) / Number(MAX_SUPPLY)) * 100).toFixed(4),
      };
    }),
  },
  contracts: CONTRACT_SPECS.map((spec) => ({
    name: spec.name,
    summary: spec.summary,
    calldata: spec.calldata,
    storage: spec.storage,
    approvesWhen: spec.approvesWhen,
    caveats: spec.caveats,
  })),
  genesis: {
    hash: blockHash(genesis.header),
    merkleRoot: genesis.header.merkleRoot,
    stateRoot: genesis.header.stateRoot,
    time: genesis.header.time,
    timeIso: new Date(genesis.header.time * 1000).toISOString(),
    bits: `0x${GENESIS_BITS.toString(16)}`,
    target: `0x${bitsToTarget(GENESIS_BITS).toString(16)}`,
    nonce: genesis.header.nonce,
    extraNonce: genesis.header.extraNonce,
    coinbaseTxid: txid(genesis.transactions[0]),
    memo: genesis.transactions[0].memo,
    reward: genesis.transactions[0].outputs[0].value,
    rewardPretty: formatDeckx(BigInt(genesis.transactions[0].outputs[0].value)),
    address: genesis.transactions[0].outputs[0].address,
    mineMs: timings.genesisMs,
    expectedAttempts: 65536,
  },
  tip: {
    height: chain.height,
    hash: chain.tipHash,
    chainWork: chain.chainWork.toString(),
    utxoCount: chain.state.utxoCount,
    contracts: chain.state.contracts().length,
  },
  supply: (() => {
    const a = chain.auditSupply();
    return {
      utxoTotal: a.utxoTotal.toString(),
      utxoTotalPretty: formatDeckx(a.utxoTotal),
      expectedSubsidy: a.expectedSubsidy.toString(),
      balanced: a.balanced,
    };
  })(),
  timeline: log,
  blocks: blocks.filter((b) => notableHeights.has(b.height)),
  allBlockHeaders: blocks.map((b) => ({
    height: b.height,
    hash: b.hash,
    time: b.time,
    txCount: b.txCount,
    nonce: b.nonce,
  })),
  contract: contractAccount
    ? {
        address: contractAccount.address,
        deployer: contractAccount.deployer,
        deployedAt: contractAccount.deployedAt,
        codeSize: contractAccount.code.length / 2,
        storage: contractAccount.storage,
        codeHex: contractAccount.code,
      }
    : null,
  volt: {
    stats: net.stats(),
    channels,
    payment: {
      ok: payment.ok,
      amountSent: payment.amountSent?.toString() ?? null,
      amountSentPretty: payment.amountSent ? formatDeckx(payment.amountSent) : null,
      feesPaid: payment.feesPaid?.toString() ?? null,
      hops: payment.route?.hops.map((h) => ({
        shortChannelId: h.shortChannelId.toString(),
        amountToForward: h.amountToForward.toString(),
        fee: h.fee.toString(),
        outgoingCltv: h.outgoingCltv,
      })) ?? [],
      forwards: payment.forwards.map((f) => ({
        node: f.node,
        amountIn: f.amountIn.toString(),
        amountOut: f.amountOut.toString(),
        fee: f.fee.toString(),
        cltv: f.cltv,
      })),
      preimage: payment.preimage ?? null,
      onionBytes: payment.onionSize ?? null,
      settleMs: timings.paymentMs,
    },
    openChannelStates: Object.values(CHANNEL_STATE),
  },
  timings,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(data, null, 2) + '\n', 'utf8');

console.log(`\nWrote ${outPath}`);
console.log(`  blocks exported : ${data.blocks.length} notable of ${chain.blocks.length}`);
console.log(`  genesis         : ${data.genesis.hash}`);
console.log(`  total time      : ${((Date.now() - started) / 1000).toFixed(1)}s`);
void toHex;
