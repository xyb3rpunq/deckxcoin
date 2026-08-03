/**
 * Hierarchical deterministic keys.
 *
 * Until now every key in this codebase came from `keyFromSeed('some string')`,
 * which is fine for tests and useless for a person. A wallet needs three
 * things that construction cannot give:
 *
 *   1. **A seed a human can write down.** BIP-39 turns 256 bits of entropy
 *      into 24 words from a fixed list, with a checksum, so a transcription
 *      error is caught rather than silently producing a different wallet.
 *   2. **Many addresses from one backup.** BIP-32 derives an unbounded tree of
 *      keys from one seed, so a user backs up once and can rotate addresses
 *      forever.
 *   3. **Address rotation that actually works.** Reusing one address links
 *      every payment you have ever received. A fresh address per payment is
 *      the single largest privacy improvement available to a wallet, and it is
 *      only practical with HD derivation.
 *
 * ── Derivation path ───────────────────────────────────────────────────────
 *
 *     m / 84' / 9333' / account' / change / index
 *
 * `84'` follows BIP-84's convention for native-segwit-style bech32 addresses,
 * which is the closest existing purpose to what DeckxCoin uses. `9333'` is the
 * coin type — deliberately the mainnet P2P port rather than a number claimed
 * from SLIP-44, because claiming a registered coin type for a chain with no
 * network would be squatting.
 *
 * `change` is 0 for addresses handed out to receive, 1 for change returning to
 * the wallet. Keeping them apart is what lets a recovering wallet scan the two
 * branches independently.
 *
 * ── The seam with BIP-340 ─────────────────────────────────────────────────
 * BIP-32 produces a 32-byte secret and a 33-byte compressed point. This chain
 * signs with BIP-340 Schnorr over x-only keys, so the compressed point is
 * discarded and `keyPair()` recomputes what it needs. The parity does not
 * survive, and does not need to — an address commits to the x-coordinate.
 */

import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { keyPair, toHex, type Hex, type KeyPair } from '../crypto.ts';

/** BIP-84's purpose: bech32 addresses. */
export const PURPOSE = 84;
/**
 * Coin type. The mainnet P2P port, not a SLIP-44 registration — claiming a
 * registered number for a chain with no network would be squatting.
 */
export const COIN_TYPE = 9333;

export const CHAIN_RECEIVE = 0;
export const CHAIN_CHANGE = 1;

/** 256 bits of entropy → 24 words. 128 would be 12 and is also standard. */
export const DEFAULT_ENTROPY_BITS = 256;

/**
 * How many consecutive unused addresses end a scan.
 *
 * BIP-44 says 20. The number is a trade: too low and a wallet misses funds
 * received on an address beyond the gap; too high and recovery scans forever.
 * Twenty has been the de facto standard for a decade.
 */
export const GAP_LIMIT = 20;

export interface DerivedKey extends KeyPair {
  readonly path: string;
  readonly chain: number;
  readonly index: number;
}

export function generateMnemonic(entropyBits = DEFAULT_ENTROPY_BITS): string {
  return bip39.generateMnemonic(wordlist, entropyBits);
}

/**
 * Validate a mnemonic's wordlist membership *and* its checksum.
 *
 * The checksum is the point. Without it, a single mistyped word silently
 * produces a valid-looking wallet that is simply somebody else's — or nobody's
 * — and the mistake is invisible until funds fail to appear.
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(normaliseMnemonic(mnemonic), wordlist);
}

/** Trim, lowercase, and collapse whitespace. Users paste from anywhere. */
export function normaliseMnemonic(mnemonic: string): string {
  return mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Words in the list that begin with `prefix`.
 *
 * BIP-39 guarantees the first four letters identify a word uniquely, which is
 * what makes recovery from a partially smudged backup possible.
 */
export function completeWord(prefix: string): string[] {
  const p = prefix.toLowerCase();
  return wordlist.filter((w) => w.startsWith(p));
}

export function isWord(word: string): boolean {
  return wordlist.includes(word.toLowerCase());
}

export const derivationPath = (account: number, chain: number, index: number): string =>
  `m/${PURPOSE}'/${COIN_TYPE}'/${account}'/${chain}/${index}`;

/**
 * A wallet's master key.
 *
 * `passphrase` is BIP-39's 25th word: it changes which wallet the mnemonic
 * opens, and there is no way to tell a wrong passphrase from a different
 * wallet. That is the point — it gives plausible deniability — and it is also
 * why forgetting it is unrecoverable.
 */
export class HdWallet {
  readonly #master: HDKey;
  readonly account: number;

  private constructor(master: HDKey, account: number) {
    this.#master = master;
    this.account = account;
  }

  static fromMnemonic(mnemonic: string, passphrase = '', account = 0): HdWallet {
    const normalised = normaliseMnemonic(mnemonic);
    if (!bip39.validateMnemonic(normalised, wordlist)) {
      throw new Error(
        'invalid mnemonic — check the spelling and word order; the checksum did not match',
      );
    }
    const seed = bip39.mnemonicToSeedSync(normalised, passphrase);
    return new HdWallet(HDKey.fromMasterSeed(seed), account);
  }

  /** Restore from a raw 64-byte seed, skipping the mnemonic entirely. */
  static fromSeed(seed: Uint8Array, account = 0): HdWallet {
    return new HdWallet(HDKey.fromMasterSeed(seed), account);
  }

  static create(entropyBits = DEFAULT_ENTROPY_BITS, passphrase = '', account = 0) {
    const mnemonic = generateMnemonic(entropyBits);
    return { mnemonic, wallet: HdWallet.fromMnemonic(mnemonic, passphrase, account) };
  }

  /** Derive one key. Throws rather than returning a wrong key on a bad path. */
  derive(chain: number, index: number): DerivedKey {
    const path = derivationPath(this.account, chain, index);
    const node = this.#master.derive(path);
    if (!node.privateKey) throw new Error(`derive: no private key at ${path}`);
    return { ...keyPair(node.privateKey), path, chain, index };
  }

  receiving(index: number): DerivedKey {
    return this.derive(CHAIN_RECEIVE, index);
  }

  change(index: number): DerivedKey {
    return this.derive(CHAIN_CHANGE, index);
  }

  /** A contiguous run of keys, for scanning. */
  range(chain: number, from: number, count: number): DerivedKey[] {
    return Array.from({ length: count }, (_, i) => this.derive(chain, from + i));
  }

  /**
   * Extended public key for the account.
   *
   * Hands a watch-only wallet the ability to derive every receiving address
   * without any ability to spend. Note the caveat that has bitten real users:
   * an xpub plus *one* child private key reveals the master private key for
   * that branch, so the two must never be shared together.
   */
  accountXpub(): string {
    return this.#master.derive(`m/${PURPOSE}'/${COIN_TYPE}'/${this.account}'`).publicExtendedKey;
  }

  /** Fingerprint of the master key. Identifies a wallet without revealing it. */
  fingerprint(): Hex {
    return toHex(new Uint8Array(new Uint32Array([this.#master.fingerprint]).buffer)).slice(0, 8);
  }

  /**
   * Zero the master key material.
   *
   * JavaScript gives no guarantee that this is the only copy — the runtime may
   * have moved the buffer during a garbage collection, and the seed passed
   * through several intermediate arrays on the way in. It is a best effort,
   * and it is worth making, but a process that has held a key should be
   * treated as compromised if the machine is.
   */
  wipe(): void {
    this.#master.wipePrivateData();
  }
}
