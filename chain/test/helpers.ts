/** Shared test scaffolding. */

import { Blockchain } from '../src/chain.ts';
import { COINBASE_MATURITY, type Utxo } from '../src/state.ts';
import { keyPairFromSeed, type KeyPair } from '../src/crypto.ts';

export interface Rig {
  chain: Blockchain;
  miner: KeyPair;
  /** Height of the chain tip. */
  height: () => number;
}

/** A regtest chain whose miner has at least one mature, spendable coinbase. */
export function rig(seed = 'test/miner'): Rig {
  const chain = Blockchain.regtest();
  const miner = keyPairFromSeed(seed);

  // One block to pay the miner, then enough to mature it.
  let t = chain.tip.header.time;
  for (let i = 0; i <= COINBASE_MATURITY; i++) {
    t += 600;
    const { result } = chain.mineBlock([], miner.address, { time: t });
    if (!result.ok) throw new Error(`rig: block ${i} rejected: ${result.error}`);
  }

  return { chain, miner, height: () => chain.height };
}

/** Advance the chain by `n` empty blocks. */
export function advance(chain: Blockchain, minerAddress: string, n: number): void {
  let t = chain.tip.header.time;
  for (let i = 0; i < n; i++) {
    t += 600;
    const { result } = chain.mineBlock([], minerAddress, { time: t });
    if (!result.ok) throw new Error(`advance: block rejected: ${result.error}`);
  }
}

/** The largest mature UTXO owned by `address`. */
export function pickUtxo(chain: Blockchain, address: string): Utxo {
  const candidates = chain.state
    .utxosFor(address)
    .filter((u) => !u.coinbase || chain.height - u.height >= COINBASE_MATURITY)
    .sort((a, b) => (a.value > b.value ? -1 : 1));
  const u = candidates[0];
  if (!u) throw new Error(`pickUtxo: no mature utxo for ${address}`);
  return u;
}
