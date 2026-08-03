/** Hashes, addresses, signatures, merkle trees, and the state trie. */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  addressFromPubkey,
  beBytes,
  beToBigInt,
  contractAddress,
  decodeAddress,
  fromHex,
  isContractAddress,
  isValidAddress,
  keyPairFromSeed,
  pointCombine,
  pointFromSecret,
  scalarCombine,
  sha256d,
  sign,
  taggedHash,
  toHex,
  utf8,
  verify,
} from '../src/crypto.ts';
import {
  EMPTY_ROOT,
  merkleProof,
  merkleRoot,
  SparseMerkleTrie,
  verifyMerkleProof,
} from '../src/merkle.ts';
import {
  bitsToTarget,
  blockSubsidy,
  blockWork,
  cumulativeIssuance,
  HALVING_INTERVAL,
  INITIAL_SUBSIDY,
  MAX_SUPPLY,
  nextBits,
  TARGET_SPACING,
  targetToBits,
  terminalHeight,
} from '../src/block.ts';
import { formatDeckx, MAX_MONEY, ZAPS_PER_DECKX } from '../src/tx.ts';

/* ------------------------------------------------------------------ hashes */

test('tagged hashes are domain-separated', () => {
  const data = utf8('same input');
  assert.notEqual(toHex(taggedHash('a', data)), toHex(taggedHash('b', data)));
  assert.equal(toHex(taggedHash('a', data)), toHex(taggedHash('a', data)));
});

test('big-endian encoding round-trips and rejects overflow', () => {
  assert.equal(beToBigInt(beBytes(123456789n, 8)), 123456789n);
  assert.equal(toHex(beBytes(255n, 1)), 'ff');
  assert.throws(() => beBytes(256n, 1), /does not fit/);
  assert.throws(() => beBytes(-1n, 4), /negative/);
});

/* --------------------------------------------------------------- addresses */

test('addresses round-trip through bech32m and reject corruption', () => {
  const key = keyPairFromSeed('primitives/alice');
  assert.match(key.address, /^dxc1/);
  assert.equal(isValidAddress(key.address), true);
  assert.equal(addressFromPubkey(key.publicKey), key.address);

  const { version, hash } = decodeAddress(key.address);
  assert.equal(version, 0);
  assert.equal(hash.length, 20);

  // Flip one character — the checksum must catch it.
  const corrupted = key.address.slice(0, -1) + (key.address.endsWith('q') ? 'p' : 'q');
  assert.equal(isValidAddress(corrupted), false);
});

test('contract addresses are deterministic, version-tagged, and nonce-dependent', () => {
  const deployer = keyPairFromSeed('primitives/deployer').address;
  const a0 = contractAddress(deployer, 0);
  const a1 = contractAddress(deployer, 1);

  assert.equal(a0, contractAddress(deployer, 0));
  assert.notEqual(a0, a1);
  assert.equal(isContractAddress(a0), true);
  assert.equal(isContractAddress(deployer), false);
  assert.equal(decodeAddress(a0).version, 1);
});

/* -------------------------------------------------------------- signatures */

test('signatures verify only against the exact digest and key', () => {
  const key = keyPairFromSeed('primitives/signer');
  const other = keyPairFromSeed('primitives/other');
  const digest = taggedHash('test', utf8('message'));
  const sig = sign(digest, key.privateKey);

  assert.equal(verify(sig, digest, key.publicKey), true);
  assert.equal(verify(sig, digest, other.publicKey), false);
  assert.equal(verify(sig, taggedHash('test', utf8('message!')), key.publicKey), false);
  assert.equal(verify('00'.repeat(64), digest, key.publicKey), false);
});

test('key derivation from a seed is deterministic across runs', () => {
  const a = keyPairFromSeed('deckxcoin/genesis/rekt');
  const b = keyPairFromSeed('deckxcoin/genesis/rekt');
  assert.equal(toHex(a.privateKey), toHex(b.privateKey));
  assert.equal(a.address, b.address);
});

/* ------------------------------------------------- elliptic-curve combining */

test('pointCombine and scalarCombine agree — the revocation-key identity', () => {
  const k1 = keyPairFromSeed('ec/base').privateKey;
  const k2 = keyPairFromSeed('ec/commitment').privateKey;
  const s1 = 0x1234_5678n;
  const s2 = 0x9abc_def0n;

  const combinedPoint = pointCombine(pointFromSecret(k1), s1, pointFromSecret(k2), s2);
  const combinedScalar = scalarCombine(k1, s1, k2, s2);

  // P₁·s₁ + P₂·s₂ must equal (k₁·s₁ + k₂·s₂)·G.
  assert.equal(toHex(combinedPoint), toHex(pointFromSecret(combinedScalar)));
});

/* ------------------------------------------------------------ merkle trees */

test('merkle root of a single transaction is that transaction', () => {
  const id = toHex(sha256d(utf8('tx')));
  assert.equal(merkleRoot([id]), id);
  assert.equal(merkleRoot([]), EMPTY_ROOT);
});

test('merkle proofs verify for every leaf, at every tree size', () => {
  for (const n of [1, 2, 3, 4, 5, 8, 9, 17]) {
    const ids = Array.from({ length: n }, (_, i) => toHex(sha256d(utf8(`tx-${n}-${i}`))));
    const root = merkleRoot(ids);
    for (let i = 0; i < n; i++) {
      const proof = merkleProof(ids, i);
      assert.equal(verifyMerkleProof(ids[i], proof, root), true, `n=${n} i=${i}`);
    }
  }
});

test('the CVE-2012-2459 duplicate-leaf construction is rejected', () => {
  const a = toHex(sha256d(utf8('a')));
  const b = toHex(sha256d(utf8('b')));
  // An odd level ending in two identical hashes is the malleability condition.
  assert.throws(() => merkleRoot([a, b, b]), /CVE-2012-2459/);
});

test('changing any transaction changes the root', () => {
  const ids = ['a', 'b', 'c', 'd'].map((s) => toHex(sha256d(utf8(s))));
  const root = merkleRoot(ids);
  const mutated = [...ids];
  mutated[2] = toHex(sha256d(utf8('c!')));
  assert.notEqual(merkleRoot(mutated), root);
});

/* --------------------------------------------------------------- state trie */

test('the state trie root is independent of insertion order', () => {
  const t1 = new SparseMerkleTrie();
  t1.set('u/a', '1');
  t1.set('u/b', '2');
  t1.set('c/x', '3');

  const t2 = new SparseMerkleTrie();
  t2.set('c/x', '3');
  t2.set('u/b', '2');
  t2.set('u/a', '1');

  assert.equal(t1.root(), t2.root());
});

test('the state trie root changes when any value changes', () => {
  const t = new SparseMerkleTrie();
  t.set('k', 'v');
  const before = t.root();
  t.set('k', 'v2');
  assert.notEqual(t.root(), before);
  t.set('k', 'v');
  assert.equal(t.root(), before);
});

test('deleting an entry restores the previous root', () => {
  const t = new SparseMerkleTrie();
  t.set('a', '1');
  const before = t.root();
  t.set('b', '2');
  assert.notEqual(t.root(), before);
  t.delete('b');
  assert.equal(t.root(), before);
});

/* ---------------------------------------------------------- monetary policy */

test('nBits and target round-trip', () => {
  for (const bits of [0x1d00ffff, 0x1f00ffff, 0x207fffff, 0x1b0404cb]) {
    assert.equal(targetToBits(bitsToTarget(bits)), bits, `bits 0x${bits.toString(16)}`);
  }
});

test('difficulty retarget is clamped to a 4x move', () => {
  const bits = 0x1d00ffff;
  const timespan = 2016 * 600;

  assert.equal(nextBits(bits, timespan), bits, 'on-schedule blocks leave difficulty alone');

  // Blocks arriving far too fast should raise difficulty, but only 4x.
  const fast = nextBits(bits, 1);
  assert.ok(bitsToTarget(fast) >= bitsToTarget(bits) / 4n - 1n);
  // Blocks arriving far too slow should lower it, capped by the max target.
  const slow = nextBits(bits, timespan * 100);
  assert.ok(bitsToTarget(slow) <= bitsToTarget(0x1f00ffff));
});

test('the halving interval is exactly 365 days of blocks', () => {
  // 365 days × 24 hours × 6 blocks/hour at 600-second spacing.
  assert.equal(HALVING_INTERVAL, 52_560);
  assert.equal((HALVING_INTERVAL * TARGET_SPACING) / 86_400, 365);
});

test('the initial subsidy is derived from the cap, not chosen', () => {
  assert.equal(MAX_SUPPLY, 21_000_000n * ZAPS_PER_DECKX);
  assert.equal(INITIAL_SUBSIDY, MAX_SUPPLY / (2n * BigInt(HALVING_INTERVAL)));
  assert.equal(INITIAL_SUBSIDY, 19_977_168_949n);
  assert.equal(formatDeckx(INITIAL_SUBSIDY), '199.77168949 DECKX');
});

test('the subsidy halves once a year and terminates', () => {
  assert.equal(blockSubsidy(0), INITIAL_SUBSIDY);
  assert.equal(blockSubsidy(HALVING_INTERVAL - 1), INITIAL_SUBSIDY, 'last block of year 1');
  assert.equal(blockSubsidy(HALVING_INTERVAL), INITIAL_SUBSIDY / 2n, 'first block of year 2');
  assert.equal(blockSubsidy(HALVING_INTERVAL * 2), INITIAL_SUBSIDY >> 2n);
  assert.equal(blockSubsidy(HALVING_INTERVAL * 64), 0n);
  assert.throws(() => blockSubsidy(-1), /negative height/);

  // The subsidy reaches zero — issuance genuinely terminates.
  assert.equal(blockSubsidy(terminalHeight() + 1), 0n);
  assert.ok(blockSubsidy(terminalHeight()) > 0n);
  assert.equal(terminalHeight(), 35 * HALVING_INTERVAL - 1, 'issuance ends after 35 years');
});

test('total issuance lands under the 21,000,000 cap without a clipped final era', () => {
  let total = 0n;
  for (let era = 0; era < 64; era++) {
    total += BigInt(HALVING_INTERVAL) * (INITIAL_SUBSIDY >> BigInt(era));
  }

  assert.ok(total <= MAX_SUPPLY, `issuance ${total} exceeds cap ${MAX_SUPPLY}`);
  // Within 0.011 DECKX of the cap — close enough that no era needs clipping.
  assert.ok(MAX_SUPPLY - total < ZAPS_PER_DECKX / 50n, `headroom too large: ${MAX_SUPPLY - total}`);
  assert.equal(total, 2_099_999_998_972_800n);
  assert.equal(MAX_MONEY, MAX_SUPPLY);
});

test('cumulativeIssuance agrees with summing block by block', () => {
  // Closed form vs brute force, across an era boundary.
  for (const h of [0, 1, 99, HALVING_INTERVAL - 2, HALVING_INTERVAL - 1, HALVING_INTERVAL, HALVING_INTERVAL + 5]) {
    let brute = 0n;
    for (let i = 0; i <= h; i++) brute += blockSubsidy(i);
    assert.equal(cumulativeIssuance(h), brute, `mismatch at height ${h}`);
  }
  assert.equal(cumulativeIssuance(-1), 0n, 'nothing issued before genesis');
});

test('half the supply exists after one year — the cost of a 365-day halving', () => {
  const afterYearOne = cumulativeIssuance(HALVING_INTERVAL - 1);

  // Exactly 52,560 × 19,977,168,949. Half of 21 M to within the truncation
  // error introduced when the subsidy was floored to a whole zap.
  assert.equal(afterYearOne, 1_049_999_999_959_440n);
  const half = MAX_SUPPLY / 2n;
  assert.ok(half - afterYearOne < ZAPS_PER_DECKX, `drift from half: ${half - afterYearOne} zaps`);

  // Issuance is genuinely front-loaded: ~99.9 % within a decade, versus
  // Bitcoin reaching that point around 2140.
  const afterTenYears = cumulativeIssuance(10 * HALVING_INTERVAL - 1);
  const pct = (Number(afterTenYears) / Number(MAX_SUPPLY)) * 100;
  assert.ok(pct > 99.8 && pct < 99.95, `ten-year issuance ${pct.toFixed(3)}%`);
});

test('chainwork rises as the target falls', () => {
  assert.ok(blockWork(0x1d00ffff) > blockWork(0x1f00ffff));
  assert.ok(blockWork(0x1f00ffff) > blockWork(0x207fffff));
});

test('DECKX formatting keeps eight decimals', () => {
  assert.equal(formatDeckx(0n), '0.00000000 DECKX');
  assert.equal(formatDeckx(1n), '0.00000001 DECKX');
  assert.equal(formatDeckx(ZAPS_PER_DECKX), '1.00000000 DECKX');
  assert.equal(formatDeckx(2_100_000_000_000_000n), '21000000.00000000 DECKX');
  void fromHex;
});
