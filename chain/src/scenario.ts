/**
 * The reference scenario.
 *
 * One script that exercises every claim the project makes, in order, on a real
 * chain with real proof of work:
 *
 *   1.  genesis                  — mined, not hardcoded
 *   2.  100 maturity blocks      — the coinbase rule is consensus, not a knob
 *   3.  first spend              — Bitcoin's §2 chain of signatures
 *   4.  contract deploy          — Ethereum's persistent state
 *   5.  contract call            — storage mutation, gas metered
 *   6.  covenant spend           — an output unlocked by code, not by a key
 *   7.  Volt channels funded     — 2-of-2 outputs on-chain
 *   8.  routed off-chain payment — Sphinx onion, HTLCs, atomic settlement
 *   9.  penalty                  — a revoked commitment punished on-chain
 *   10. cooperative close        — the happy path back to L1
 *
 * The website's explorer is fed by this, so every number on the site is a
 * number this code produced. Nothing on that page is a mock.
 */

import { Blockchain } from './chain.ts';
import { blockHash, blockSubsidy, GENESIS_BITS, GENESIS_MEMO } from './block.ts';
import { COINBASE_MATURITY, type Utxo } from './state.ts';
import {
  callTx,
  deployTx,
  formatDeckx,
  signInput,
  signTx,
  transferTx,
  txid,
  ZAPS_PER_DECKX,
  type Transaction,
} from './tx.ts';
import { contractAddress, keyPairFromSeed, toHex, type Hex } from './crypto.ts';
import { timeVault } from './contracts/index.ts';
import { VoltNetwork } from './volt/network.ts';
import { encodeInvoice } from './volt/invoice.ts';
import type { PaymentResult } from './volt/network.ts';

export interface ScenarioLog {
  readonly step: number;
  readonly title: string;
  readonly detail: string;
  readonly txid?: Hex;
  readonly height?: number;
}

export interface ScenarioResult {
  readonly chain: Blockchain;
  readonly net: VoltNetwork;
  readonly log: ScenarioLog[];
  readonly contract: string;
  readonly payment: PaymentResult;
  readonly timings: Record<string, number>;
}

const DECKX = ZAPS_PER_DECKX;

/**
 * The REKT Vault contract.
 *
 * A covenant, not a token. It guards an output and releases it only to a
 * pre-declared beneficiary, and only after a pre-declared block height. In
 * Bitcoin this needs a covenant soft fork (CTV/CSFS, still unactivated as of
 * 2026); in Ethereum it needs a contract that custodies the funds. DeckxCoin
 * needs neither: the output stays a UTXO, and the contract is only asked
 * "may this spend proceed?".
 *
 * Storage:
 *   slot 0 — unlock height
 *   slot 1 — beneficiary address word
 *   slot 2 — number of release attempts, successful or not
 *
 * Returns `[approved, beneficiary]`. The chain checks that some output of the
 * spending transaction actually pays `beneficiary`, so an approval cannot be
 * replayed by a third party to redirect the funds.
 */
/**
 * The scenario deploys `TimeVault` from the standard covenant library.
 *
 * Re-exported under its historical name so existing imports keep working —
 * the contract itself now lives in `src/contracts/`, alongside Escrow,
 * Vesting, MultiSig and AtomicSwap, and is tested there.
 */
export function rektVaultCode(unlockHeight: number, beneficiary: string): Uint8Array {
  return timeVault(unlockHeight, beneficiary).code;
}

export { REKT_TOPIC } from './contracts/lib.ts';

export function runScenario(opts: { verbose?: boolean } = {}): ScenarioResult {
  const log: ScenarioLog[] = [];
  const timings: Record<string, number> = {};
  const say = (step: number, title: string, detail: string, extra: Partial<ScenarioLog> = {}) => {
    log.push({ step, title, detail, ...extra });
    if (opts.verbose) console.log(`[${String(step).padStart(2, '0')}] ${title}\n     ${detail}`);
  };

  /* -- 1. genesis --------------------------------------------------- */
  let mark = Date.now();
  const chain = Blockchain.create();
  timings.genesisMs = Date.now() - mark;

  const genesisKey = Blockchain.genesisKey();
  say(1, 'Genesis mined', `${blockHash(chain.tip.header)} · bits 0x${GENESIS_BITS.toString(16)} · ${timings.genesisMs}ms`, {
    txid: txid(chain.tip.transactions[0]),
    height: 0,
  });

  /* -- 2. maturity -------------------------------------------------- */
  const alice = keyPairFromSeed('deckx/alice');
  const bob = keyPairFromSeed('deckx/bob');
  const carol = keyPairFromSeed('deckx/carol');
  const miner = keyPairFromSeed('deckx/miner');

  mark = Date.now();
  let t = chain.tip.header.time;
  for (let i = 0; i < COINBASE_MATURITY; i++) {
    t += 600;
    const { result } = chain.mineBlock([], miner.address, { time: t });
    if (!result.ok) throw new Error(`scenario: maturity block ${i} rejected: ${result.error}`);
  }
  timings.maturityMs = Date.now() - mark;
  say(2, 'Coinbase matured', `${COINBASE_MATURITY} blocks mined in ${timings.maturityMs}ms · tip height ${chain.height}`, {
    height: chain.height,
  });

  /* -- 3. first spend ----------------------------------------------- */
  const genesisCoinbase = chain.blocks[0].transactions[0];
  const genesisValue = blockSubsidy(0);
  const fee = 5_000n;
  const toAlice = 30n * DECKX;

  let spend = transferTx({
    inputs: [{ txid: txid(genesisCoinbase), vout: 0 }],
    outputs: [
      { value: toAlice.toString(), address: alice.address },
      { value: (genesisValue - toAlice - fee).toString(), address: genesisKey.address },
    ],
    memo: 'first spend from the genesis coinbase',
  });
  spend = signTx(spend, genesisKey, [{ value: genesisValue, address: genesisKey.address }]);

  t += 600;
  const spendBlock = chain.mineBlock([spend], miner.address, { time: t });
  if (!spendBlock.result.ok) throw new Error(`scenario: first spend rejected: ${spendBlock.result.error}`);
  say(3, 'First transaction', `${formatDeckx(toAlice)} from genesis → alice · fee ${fee} zaps`, {
    txid: txid(spend),
    height: spendBlock.result.height,
  });

  /* -- 4. deploy the vault ------------------------------------------ */
  const unlockHeight = chain.height + 4;
  const vaultCode = rektVaultCode(unlockHeight, carol.address);
  const gasLimit = 200_000;
  const gasPrice = 1n;
  const gasBudget = BigInt(gasLimit) * gasPrice;

  const aliceUtxo = pick(chain, alice.address);
  const vaultEndowment = 5n * DECKX;
  const vaultAddress = contractAddress(alice.address, 0);

  let deploy = deployTx({
    inputs: [{ txid: aliceUtxo.txid, vout: aliceUtxo.vout }],
    outputs: [
      { value: vaultEndowment.toString(), address: vaultAddress },
      { value: (aliceUtxo.value - vaultEndowment - gasBudget).toString(), address: alice.address },
    ],
    code: toHex(vaultCode),
    gasLimit,
    gasPrice,
    nonce: 0,
    memo: 'deploy REKT vault',
  });
  deploy = signTx(deploy, alice, [{ value: aliceUtxo.value, address: aliceUtxo.address }]);

  t += 600;
  const deployBlock = chain.mineBlock([deploy], miner.address, { time: t });
  if (!deployBlock.result.ok) throw new Error(`scenario: deploy rejected: ${deployBlock.result.error}`);
  const vault = chain.state.getContract(vaultAddress);
  if (!vault) throw new Error('scenario: vault was not created');
  say(4, 'Contract deployed', `REKT Vault at ${vaultAddress} · unlocks at height ${unlockHeight} · beneficiary carol`, {
    txid: txid(deploy),
    height: deployBlock.result.height,
  });

  /* -- 5. call before unlock: the covenant refuses ------------------- */
  const early = buildVaultSpend(chain, alice, vaultAddress, carol.address, gasLimit, gasPrice);
  const earlyResult = chain.applyTransaction(early, chain.state.clone(), {
    height: chain.height + 1,
    time: t + 600,
  });
  say(5, 'Covenant refuses early spend', earlyResult.ok
    ? 'UNEXPECTED: the vault approved a premature release'
    : `rejected — ${earlyResult.error}`);
  if (earlyResult.ok) throw new Error('scenario: vault approved a premature spend');

  /* -- 6. after unlock: the covenant approves ------------------------ */
  while (chain.height < unlockHeight) {
    t += 600;
    chain.mineBlock([], miner.address, { time: t });
  }
  const release = buildVaultSpend(chain, alice, vaultAddress, carol.address, gasLimit, gasPrice);
  t += 600;
  const releaseBlock = chain.mineBlock([release], miner.address, { time: t });
  if (!releaseBlock.result.ok) throw new Error(`scenario: vault release rejected: ${releaseBlock.result.error}`);
  say(6, 'Covenant releases', `vault paid ${formatDeckx(vaultEndowment)} to carol at height ${chain.height} · gas ${releaseBlock.result.gasUsed} · no key ever signed for the vault`, {
    txid: txid(release),
    height: releaseBlock.result.height,
  });

  /* -- 7. Volt channels --------------------------------------------- */
  const net = new VoltNetwork();
  const vAlice = net.addNode('alice', 'deckx/volt/alice');
  const vBob = net.addNode('bob', 'deckx/volt/bob');
  const vCarol = net.addNode('carol', 'deckx/volt/carol');

  const funders = chain.state
    .utxosFor(miner.address)
    .filter((u) => chain.height - u.height >= COINBASE_MATURITY)
    .sort((a, b) => (a.value > b.value ? -1 : 1));

  const ab = net.openChannel({
    a: vAlice, b: vBob, capacity: 4n * DECKX,
    funding: funders[0], funderKey: miner, changeAddress: miner.address,
    policy: { baseFee: 1_000n, feeRatePpm: 250n, cltvDelta: 40 },
  });
  const bc = net.openChannel({
    a: vBob, b: vCarol, capacity: 4n * DECKX,
    funding: funders[1], funderKey: miner, changeAddress: miner.address,
    policy: { baseFee: 1_500n, feeRatePpm: 400n, cltvDelta: 80 },
  });

  t += 600;
  const openBlock = chain.mineBlock([ab.fundingTx, bc.fundingTx], miner.address, { time: t });
  if (!openBlock.result.ok) throw new Error(`scenario: channel funding rejected: ${openBlock.result.error}`);
  net.confirmAll(chain);
  say(7, 'Volt channels opened', `alice↔bob and bob↔carol · ${formatDeckx(8n * DECKX)} total capacity · 2 on-chain transactions`, {
    txid: txid(ab.fundingTx),
    height: openBlock.result.height,
  });

  /* -- 8. routed off-chain payment ----------------------------------- */
  mark = Date.now();
  const invoice = vCarol.invoice(75_000_000n, 'REKT hoodie, size L', {
    seed: 'deckx/demo/invoice',
    timestamp: t,
  });
  const payment = net.payInvoice(vAlice, encodeInvoice(invoice), {
    currentHeight: chain.height,
    now: t,
  });
  timings.paymentMs = Date.now() - mark;
  if (!payment.ok) throw new Error(`scenario: routed payment failed: ${payment.error}`);
  say(8, 'Routed payment settled', `alice → bob → carol · ${formatDeckx(payment.amountSent!)} sent · ${payment.feesPaid} zaps routing fee · ${timings.paymentMs}ms · 0 on-chain transactions`);

  // A few more payments so the channel has real history to show.
  for (let i = 0; i < 12; i++) {
    const inv = vCarol.invoice(1_000_000n + BigInt(i) * 250_000n, `micro ${i}`, {
      seed: `deckx/demo/micro/${i}`,
      timestamp: t,
    });
    net.payInvoice(vAlice, encodeInvoice(inv), { currentHeight: chain.height, now: t });
  }
  say(9, 'Micro-payment burst', `12 further routed payments · channel now at commitment #${ab.channel.commitmentNumber} · still 0 on-chain transactions`);

  /* -- 9. penalty ---------------------------------------------------- */
  const staleNumber = 1;
  const stale = ab.channel.history[staleNumber].forA;
  t += 600;
  const cheatBlock = chain.mineBlock([stale], miner.address, { time: t });
  if (!cheatBlock.result.ok) throw new Error(`scenario: stale commitment rejected: ${cheatBlock.result.error}`);

  const penalty = ab.channel.penaltyFor(stale, staleNumber, 'a', vBob.address, 1_000n);
  t += 600;
  const penaltyBlock = chain.mineBlock([penalty], miner.address, { time: t });
  if (!penaltyBlock.result.ok) throw new Error(`scenario: penalty rejected: ${penaltyBlock.result.error}`);
  const swept = BigInt(penalty.outputs[0].value);
  say(10, 'Penalty enforced', `alice broadcast commitment #${staleNumber}; bob swept ${formatDeckx(swept)} — the entire channel`, {
    txid: txid(penalty),
    height: penaltyBlock.result.height,
  });

  /* -- 10. cooperative close ----------------------------------------- */
  const close = bc.channel.cooperativeClose(1_000n);
  t += 600;
  const closeBlock = chain.mineBlock([close], miner.address, { time: t });
  if (!closeBlock.result.ok) throw new Error(`scenario: close rejected: ${closeBlock.result.error}`);
  say(11, 'Cooperative close', `bob↔carol settled to L1 in one transaction · ${bc.channel.commitmentNumber} off-chain states collapsed`, {
    txid: txid(close),
    height: closeBlock.result.height,
  });

  const audit = chain.auditSupply();
  say(12, 'Supply audit', audit.balanced
    ? `balanced — ${formatDeckx(audit.utxoTotal)} in existence, exactly the sum of ${chain.height + 1} subsidies`
    : `DRIFT: ${audit.utxoTotal} vs ${audit.expectedSubsidy}`);
  if (!audit.balanced) throw new Error('scenario: supply audit failed');

  return { chain, net, log, contract: vaultAddress, payment, timings };
}

/* ------------------------------------------------------------------ helpers */

function pick(chain: Blockchain, address: string): Utxo {
  const u = chain.state
    .utxosFor(address)
    .filter((x) => !x.coinbase || chain.height - x.height >= COINBASE_MATURITY)
    .sort((a, b) => (a.value > b.value ? -1 : 1))[0];
  if (!u) throw new Error(`scenario: no spendable utxo for ${address}`);
  return u;
}

/**
 * Spend the vault's covenant-locked output to its beneficiary.
 *
 * Two inputs: the vault UTXO (unlocked by contract approval, no signature at
 * all) and one of the caller's own coins to pay the gas. The caller cannot
 * redirect the vault — the chain checks that some output pays the
 * beneficiary word the contract returned.
 */
function buildVaultSpend(
  chain: Blockchain,
  caller: ReturnType<typeof keyPairFromSeed>,
  vaultAddress: string,
  beneficiary: string,
  gasLimit: number,
  gasPrice: bigint,
): Transaction {
  const vaultUtxo = chain.state.utxosFor(vaultAddress)[0];
  if (!vaultUtxo) throw new Error('buildVaultSpend: vault holds no output');
  const funding = pick(chain, caller.address);
  const gasBudget = BigInt(gasLimit) * gasPrice;

  let tx = callTx({
    inputs: [
      { txid: vaultUtxo.txid, vout: vaultUtxo.vout },
      { txid: funding.txid, vout: funding.vout },
    ],
    outputs: [
      { value: vaultUtxo.value.toString(), address: beneficiary },
      { value: (funding.value - gasBudget).toString(), address: caller.address },
    ],
    target: vaultAddress,
    gasLimit,
    gasPrice,
    nonce: chain.state.nonceOf(caller.address),
    memo: 'release REKT vault',
  });
  // Only input 1 needs a signature; input 0 is unlocked by the contract.
  tx = signInput(tx, 1, caller, { value: funding.value, address: funding.address });
  return tx;
}

export { GENESIS_MEMO };
