/**
 * World state.
 *
 * Two sub-states live side by side, and the block header commits to both:
 *
 *   utxos     — Bitcoin's set of unspent outputs. Ownership of value.
 *   contracts — Ethereum's account trie. Code, storage, and balance.
 *
 * The `stateRoot` is a single trie over both, with disjoint key prefixes
 * (`u/…` and `c/…`). One root, one commitment, no ambiguity about which
 * sub-state a proof refers to.
 */

import { taggedHex, type Hex } from './crypto.ts';
import { SparseMerkleTrie } from './merkle.ts';
import type { OutputScript } from './tx.ts';

export interface Utxo {
  readonly txid: Hex;
  readonly vout: number;
  readonly value: bigint;
  readonly address: string;
  readonly script?: OutputScript;
  /** Block height that created it. Coinbase maturity is measured from here. */
  readonly height: number;
  readonly coinbase: boolean;
}

/**
 * A deployed contract.
 *
 * Note what is *absent*: a balance field. DeckxCoin contracts do not custody
 * value. Funds sent to a contract address stay ordinary UTXOs — they are
 * simply locked by code rather than by a key, and `balanceOf` sums them like
 * any other address. This removes the "contract holds the money" failure mode
 * that every major Ethereum exploit has depended on: there is no pot to drain,
 * only individual outputs whose release the contract may approve or refuse.
 */
export interface ContractAccount {
  readonly address: string;
  readonly code: Hex;
  readonly storage: Record<string, string>;
  readonly deployedAt: number;
  readonly deployer: string;
}

export const outpoint = (txid: Hex, vout: number): string => `${txid}:${vout}`;

/** Coinbase outputs are unspendable for this many blocks — reorg safety, Bitcoin's 100. */
export const COINBASE_MATURITY = 100;

export class WorldState {
  readonly #utxos = new Map<string, Utxo>();
  readonly #contracts = new Map<string, ContractAccount>();
  readonly #nonces = new Map<string, number>();

  /* ------------------------------------------------------------- utxo set */

  addUtxo(u: Utxo): void {
    const key = outpoint(u.txid, u.vout);
    if (this.#utxos.has(key)) throw new Error(`addUtxo: outpoint already exists ${key}`);
    this.#utxos.set(key, u);
  }

  getUtxo(txid: Hex, vout: number): Utxo | undefined {
    return this.#utxos.get(outpoint(txid, vout));
  }

  spendUtxo(txid: Hex, vout: number): Utxo {
    const key = outpoint(txid, vout);
    const u = this.#utxos.get(key);
    if (!u) throw new Error(`spendUtxo: unknown or already-spent outpoint ${key}`);
    this.#utxos.delete(key);
    return u;
  }

  hasUtxo(txid: Hex, vout: number): boolean {
    return this.#utxos.has(outpoint(txid, vout));
  }

  utxos(): Utxo[] {
    return [...this.#utxos.values()];
  }

  utxosFor(address: string): Utxo[] {
    return this.utxos().filter((u) => u.address === address);
  }

  balanceOf(address: string): bigint {
    return this.utxosFor(address).reduce((sum, u) => sum + u.value, 0n);
  }

  /** Total value in existence according to the UTXO set — the supply audit. */
  totalSupply(): bigint {
    let sum = 0n;
    for (const u of this.#utxos.values()) sum += u.value;
    return sum;
  }

  get utxoCount(): number {
    return this.#utxos.size;
  }

  /* ----------------------------------------------------------- contracts */

  putContract(c: ContractAccount): void {
    this.#contracts.set(c.address, c);
  }

  getContract(address: string): ContractAccount | undefined {
    return this.#contracts.get(address);
  }

  contracts(): ContractAccount[] {
    return [...this.#contracts.values()];
  }

  setStorage(address: string, storage: Record<string, string>): void {
    const c = this.#contracts.get(address);
    if (!c) throw new Error(`setStorage: unknown contract ${address}`);
    this.#contracts.set(address, { ...c, storage });
  }

  /* -------------------------------------------------------------- nonces */

  nonceOf(address: string): number {
    return this.#nonces.get(address) ?? 0;
  }

  bumpNonce(address: string): number {
    const next = this.nonceOf(address) + 1;
    this.#nonces.set(address, next);
    return next;
  }

  /* ----------------------------------------------------------- state root */

  /**
   * Canonical commitment over the whole world state. Recomputed from scratch
   * rather than maintained incrementally — the reference implementation
   * prioritises being obviously correct over being fast, and a divergent
   * incremental root is the hardest class of consensus bug to debug.
   */
  stateRoot(): Hex {
    const trie = new SparseMerkleTrie();

    for (const u of this.#utxos.values()) {
      trie.set(
        `u/${outpoint(u.txid, u.vout)}`,
        `${u.value}|${u.address}|${u.script ? JSON.stringify(u.script) : ''}|${u.height}|${u.coinbase ? 1 : 0}`,
      );
    }

    for (const c of this.#contracts.values()) {
      const storageRoot = SparseMerkleTrie.from(c.storage).root();
      trie.set(
        `c/${c.address}`,
        `${taggedHex('DeckxCoin/codehash', new TextEncoder().encode(c.code))}|${storageRoot}|${c.deployedAt}|${c.deployer}`,
      );
    }

    for (const [address, nonce] of this.#nonces) {
      trie.set(`n/${address}`, String(nonce));
    }

    return trie.root();
  }

  /* ------------------------------------------------------------ snapshots */

  snapshot(): WorldStateSnapshot {
    return {
      utxos: this.utxos().map((u) => ({ ...u, value: u.value.toString() })),
      contracts: this.contracts(),
      nonces: Object.fromEntries(this.#nonces),
    };
  }

  static restore(snap: WorldStateSnapshot): WorldState {
    const s = new WorldState();
    for (const u of snap.utxos) s.addUtxo({ ...u, value: BigInt(u.value) });
    for (const c of snap.contracts) s.putContract(c);
    for (const [address, nonce] of Object.entries(snap.nonces)) s.#nonces.set(address, nonce);
    return s;
  }

  clone(): WorldState {
    return WorldState.restore(this.snapshot());
  }
}

export interface WorldStateSnapshot {
  readonly utxos: ReadonlyArray<Omit<Utxo, 'value'> & { value: string }>;
  readonly contracts: readonly ContractAccount[];
  readonly nonces: Record<string, number>;
}
