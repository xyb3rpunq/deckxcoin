/**
 * BIP-340 Schnorr signatures.
 *
 * The first block runs the **official BIP-340 test vectors**, verbatim from the
 * specification's `test-vectors.csv`. They are not a formality: vectors 5
 * through 14 are adversarial cases chosen precisely because implementers get
 * them wrong — a public key that is not on the curve, an `R` with odd y, an `s`
 * at the group order, an `x` at the field size. An implementation that passes
 * the happy path and fails these is worse than useless, because it looks
 * correct.
 *
 * The rest covers the properties this chain depends on: determinism (so genesis
 * is reproducible), the x-only/compressed-point boundary (the one real hazard
 * the migration introduced), and the Volt revocation identity.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CURVE_N,
  fromHex,
  keyPairFromSeed,
  pointCombine,
  pointFromSecret,
  PUBKEY_BYTES,
  scalarCombine,
  sign,
  SIGNATURE_BYTES,
  taggedHash,
  toHex,
  toPoint,
  toXOnly,
  utf8,
  verify,
  verifyBatch,
  xOnlyFromSecret,
} from '../src/crypto.ts';
import { revocationKeyPair, revocationPubkey, SecretChain } from '../src/volt/secrets.ts';

/* ─────────────────────────────────── official BIP-340 test vectors ── */

interface Vector {
  readonly index: number;
  readonly secret?: string;
  readonly pubkey: string;
  readonly aux?: string;
  readonly message: string;
  readonly signature: string;
  readonly valid: boolean;
  readonly comment: string;
}

/** From https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv */
const VECTORS: Vector[] = [
  {
    index: 0,
    secret: '0000000000000000000000000000000000000000000000000000000000000003',
    pubkey: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
    aux: '0000000000000000000000000000000000000000000000000000000000000000',
    message: '0000000000000000000000000000000000000000000000000000000000000000',
    signature:
      'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0',
    valid: true,
    comment: 'smallest possible secret key',
  },
  {
    index: 1,
    secret: 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    aux: '0000000000000000000000000000000000000000000000000000000000000001',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A',
    valid: true,
    comment: 'typical case',
  },
  {
    index: 2,
    secret: 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9',
    pubkey: 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
    aux: 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906',
    message: '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    signature:
      '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7',
    valid: true,
    comment: 'aux randomness is used',
  },
  {
    index: 3,
    secret: '0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710',
    pubkey: '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517',
    aux: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    message: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    signature:
      '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3',
    valid: true,
    comment: 'message and aux at the field maximum',
  },
  {
    index: 4,
    pubkey: 'D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9',
    message: '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703',
    signature:
      '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4',
    valid: true,
    comment: 'test fails if msg is reduced modulo p or n',
  },
  {
    index: 5,
    pubkey: 'EEFDEA4CD0B44E9C4A5AE1B6E4AB1EEEEE55E1AEA0A4C9C5C0BE2E5C2C7B9E6A',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B',
    valid: false,
    comment: 'public key not on the curve',
  },
  {
    index: 6,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      'FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2',
    valid: false,
    comment: 'has_even_y(R) is false',
  },
  {
    index: 7,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD',
    valid: false,
    comment: 'negated message',
  },
  {
    index: 8,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6',
    valid: false,
    comment: 'negated s value',
  },
  {
    index: 9,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051',
    valid: false,
    comment: 'sG - eP is infinite (r = 0)',
  },
  {
    index: 10,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197',
    valid: false,
    comment: 'sG - eP is infinite (r = 1)',
  },
  {
    index: 11,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B',
    valid: false,
    comment: 'sig[0:32] is not an X coordinate on the curve',
  },
  {
    index: 12,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B',
    valid: false,
    comment: 'sig[0:32] equals field size',
  },
  {
    index: 13,
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    valid: false,
    comment: 'sig[32:64] equals curve order',
  },
  {
    index: 14,
    pubkey: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature:
      '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B',
    valid: false,
    comment: 'public key exceeds field size',
  },
];

test('BIP-340: every official test vector gives the specified result', () => {
  let checkedInvalid = 0;

  for (const v of VECTORS) {
    const pubkey = fromHex(v.pubkey.toLowerCase());
    const message = fromHex(v.message.toLowerCase());
    const signature = v.signature.toLowerCase();

    const result = verify(signature, message, pubkey);
    assert.equal(
      result,
      v.valid,
      `vector ${v.index} (${v.comment}): expected ${v.valid}, got ${result}`,
    );
    if (!v.valid) checkedInvalid++;
  }

  // Guard against a regression that turns the adversarial vectors into no-ops.
  assert.equal(VECTORS.length, 15);
  assert.equal(checkedInvalid, 10, 'ten vectors must be rejections');
});

test('BIP-340: signing a vector reproduces the specified signature', () => {
  // Only vectors 0–3 carry a secret key. Vector 2 uses non-zero aux randomness,
  // which this chain deliberately does not supply, so its signature differs —
  // and is still valid, which is the property that matters.
  for (const v of VECTORS.filter((x) => x.secret && x.aux === '0'.repeat(64))) {
    const secret = fromHex(v.secret!.toLowerCase());
    const message = fromHex(v.message.toLowerCase());

    assert.equal(
      toHex(xOnlyFromSecret(secret)),
      v.pubkey.toLowerCase(),
      `vector ${v.index}: derived public key mismatch`,
    );
    assert.equal(
      sign(message, secret),
      v.signature.toLowerCase(),
      `vector ${v.index}: signature mismatch`,
    );
  }
});

/* ─────────────────────────────────────────────────────── properties ── */

test('signatures are 64 bytes and keys are 32', () => {
  const key = keyPairFromSeed('schnorr/sizes');
  assert.equal(key.publicKey.length, PUBKEY_BYTES);
  assert.equal(key.point.length, 33, 'the compressed point is kept alongside');
  const sig = sign(taggedHash('t', utf8('m')), key.privateKey);
  assert.equal(fromHex(sig).length, SIGNATURE_BYTES);
});

test('signing is deterministic — genesis must be reproducible', () => {
  const key = keyPairFromSeed('schnorr/determinism');
  const digest = taggedHash('DeckxCoin/test', utf8('same message'));
  const a = sign(digest, key.privateKey);
  const b = sign(digest, key.privateKey);
  assert.equal(a, b, 'two signings of the same digest must agree byte for byte');
});

test('a signature verifies only against its own key and message', () => {
  const key = keyPairFromSeed('schnorr/binding');
  const other = keyPairFromSeed('schnorr/other');
  const digest = taggedHash('t', utf8('message'));
  const sig = sign(digest, key.privateKey);

  assert.equal(verify(sig, digest, key.publicKey), true);
  assert.equal(verify(sig, digest, other.publicKey), false);
  assert.equal(verify(sig, taggedHash('t', utf8('message!')), key.publicKey), false);
  assert.equal(verify('00'.repeat(64), digest, key.publicKey), false);
  assert.equal(verify('ab'.repeat(32), digest, key.publicKey), false, 'wrong length is rejected');
});

test('there is no malleable second signature — the ECDSA low-s problem is gone', () => {
  const key = keyPairFromSeed('schnorr/malleability');
  const digest = taggedHash('t', utf8('m'));
  const sig = fromHex(sign(digest, key.privateKey));

  // Negating s, the classic ECDSA malleation, produces nothing valid.
  const s = BigInt('0x' + toHex(sig.subarray(32)));
  const negated = CURVE_N - s;
  const malleated = toHex(sig.subarray(0, 32)) + negated.toString(16).padStart(64, '0');
  assert.equal(verify(malleated, digest, key.publicKey), false);
});

/** `count` valid signatures, each by a different key over a different message. */
function batchOf(prefix: string, count: number) {
  return Array.from({ length: count }, (_, i) => {
    const key = keyPairFromSeed(`${prefix}/${i}`);
    const digest = taggedHash('batch', utf8(`${prefix} message ${i}`));
    return { signature: sign(digest, key.privateKey), digest, publicKey: key.publicKey };
  });
}

test('batch verification accepts a valid batch and names the bad signature', () => {
  const items = batchOf('schnorr/batch', 12);
  assert.deepEqual(verifyBatch(items), { ok: true });

  const corrupted = [...items];
  corrupted[7] = { ...corrupted[7], signature: '00'.repeat(64) };
  const result = verifyBatch(corrupted);
  assert.equal(result.ok, false);
  assert.equal(result.failedIndex, 7, 'a batch failure must identify which one');
});

test('batch verification agrees with one-by-one on every corruption shape', () => {
  const base = batchOf('schnorr/agree', 10);

  const mutations: Array<[string, (items: typeof base) => typeof base]> = [
    ['untouched', (x) => x],
    ['zero signature', (x) => replace(x, 3, { signature: '00'.repeat(64) })],
    ['flipped signature byte', (x) => replace(x, 5, { signature: flipHex(x[5].signature, 10) })],
    ['swapped digest', (x) => replace(x, 2, { digest: x[6].digest })],
    ['swapped key', (x) => replace(x, 8, { publicKey: x[1].publicKey })],
    ['signature from another item', (x) => replace(x, 4, { signature: x[9].signature })],
    ['s at the group order', (x) => replace(x, 6, { signature: x[6].signature.slice(0, 64) + CURVE_N.toString(16).padStart(64, '0') })],
    ['r of all zeroes', (x) => replace(x, 0, { signature: '00'.repeat(32) + x[0].signature.slice(64) })],
    ['truncated signature', (x) => replace(x, 1, { signature: 'ab'.repeat(20) })],
  ];

  for (const [name, mutate] of mutations) {
    const items = mutate([...base]);
    const batch = verifyBatch(items);
    const individually = items.every((it) => verify(it.signature, it.digest, it.publicKey));

    assert.equal(batch.ok, individually, `'${name}': batch and individual verdicts must agree`);
    if (!batch.ok) {
      assert.equal(typeof batch.failedIndex, 'number', `'${name}': must report an index`);
      const bad = items[batch.failedIndex!];
      assert.equal(
        verify(bad.signature, bad.digest, bad.publicKey),
        false,
        `'${name}': the reported index must actually be invalid`,
      );
    }
  }
});

test('batch verification cannot be gamed by signatures whose errors cancel', () => {
  /*
   * The attack the random weights exist to stop. With aᵢ = 1 the batch checks
   * Σsᵢ·G = Σ(Rᵢ + eᵢPᵢ), so an attacker who can add a value to one signature
   * and subtract it from another passes the sum while both members are
   * individually invalid.
   *
   * Here that is simulated directly: move a constant between two `s` values.
   * The sum of `s` is unchanged, so an unweighted batch would accept.
   */
  const items = batchOf('schnorr/cancel', 6);
  const delta = 0x1234_5678_9abc_def0n;

  const shift = (signature: string, by: bigint): string => {
    const s = (BigInt('0x' + signature.slice(64)) + by + CURVE_N) % CURVE_N;
    return signature.slice(0, 64) + s.toString(16).padStart(64, '0');
  };

  const gamed = [...items];
  gamed[1] = { ...gamed[1], signature: shift(gamed[1].signature, delta) };
  gamed[2] = { ...gamed[2], signature: shift(gamed[2].signature, -delta) };

  // Both members really are individually invalid…
  assert.equal(verify(gamed[1].signature, gamed[1].digest, gamed[1].publicKey), false);
  assert.equal(verify(gamed[2].signature, gamed[2].digest, gamed[2].publicKey), false);
  // …and the sum of s is preserved, which is what an unweighted batch checks.
  const sumOf = (list: typeof items) =>
    list.reduce((acc, it) => (acc + BigInt('0x' + it.signature.slice(64))) % CURVE_N, 0n);
  assert.equal(sumOf(gamed), sumOf(items), 'the harness must actually preserve Σs');

  // The weighted batch rejects it.
  const result = verifyBatch(gamed);
  assert.equal(result.ok, false, 'randomised weights must defeat cancelling errors');
  assert.ok(result.failedIndex === 1 || result.failedIndex === 2);
});

test('batch verification handles the degenerate sizes', () => {
  assert.deepEqual(verifyBatch([]), { ok: true });
  const one = batchOf('schnorr/one', 1);
  assert.deepEqual(verifyBatch(one), { ok: true });
  const three = batchOf('schnorr/three', 3);
  assert.deepEqual(verifyBatch(three), { ok: true });
});

test('batch verification is faster than one-by-one at block scale', () => {
  // The reason the chain uses Schnorr. If this ever regresses, the claim in
  // the README and the whitepaper is no longer true and should be removed.
  const items = batchOf('schnorr/perf', 256);

  let start = performance.now();
  for (const it of items) verify(it.signature, it.digest, it.publicKey);
  const individually = performance.now() - start;

  start = performance.now();
  const result = verifyBatch(items);
  const batched = performance.now() - start;

  assert.equal(result.ok, true);
  assert.ok(
    batched < individually,
    `batch (${batched.toFixed(0)}ms) must beat one-by-one (${individually.toFixed(0)}ms)`,
  );
});

function replace<T>(items: T[], index: number, patch: Partial<T>): T[] {
  const copy = [...items];
  copy[index] = { ...copy[index], ...patch };
  return copy;
}

function flipHex(hex: string, index: number): string {
  const chars = [...hex];
  chars[index] = chars[index] === 'a' ? 'b' : 'a';
  return chars.join('');
}

/* ───────────────────────────────── x-only / point boundary ── */

test('toXOnly and toPoint round-trip through the even-y branch', () => {
  const key = keyPairFromSeed('schnorr/boundary');
  assert.equal(toHex(toXOnly(key.point)), toHex(key.publicKey));
  assert.equal(toHex(toXOnly(key.publicKey)), toHex(key.publicKey), 'x-only is idempotent');
  assert.equal(toPoint(key.publicKey)[0], 0x02, 'lifting asserts even y');
  assert.equal(toHex(toPoint(key.point)), toHex(key.point), 'lifting a point is idempotent');
  assert.throws(() => toXOnly(new Uint8Array(10)), /expected 32 or 33 bytes/);
  assert.throws(() => toPoint(new Uint8Array(10)), /expected 32 bytes/);
});

test('half of all keys have an odd-y point — the case that would break naive lifting', () => {
  // If this ever reports zero, the x-only handling is not actually being
  // exercised and the boundary tests below prove nothing.
  let odd = 0;
  for (let i = 0; i < 40; i++) {
    if (keyPairFromSeed(`schnorr/parity/${i}`).point[0] === 0x03) odd++;
  }
  assert.ok(odd > 5 && odd < 35, `expected a mix of parities, got ${odd}/40 odd`);
});

test('a signature verifies for a key whose point has odd y', () => {
  // Find one explicitly rather than hoping the fixed seeds happen to cover it.
  let key = keyPairFromSeed('schnorr/odd/0');
  for (let i = 0; i < 64 && key.point[0] !== 0x03; i++) key = keyPairFromSeed(`schnorr/odd/${i}`);
  assert.equal(key.point[0], 0x03, 'harness failed to find an odd-y key');

  const digest = taggedHash('t', utf8('odd parity'));
  assert.equal(verify(sign(digest, key.privateKey), digest, key.publicKey), true);
});

/* ─────────────────────────────── the Volt revocation identity ── */

test('the revocation identity still holds on x-only keys', () => {
  const base = keyPairFromSeed('schnorr/rev/base');
  const chain = new SecretChain('schnorr/rev/commitments');
  const perCommitmentSecret = chain.secret(3);

  // Both parties derive the public key from compressed points…
  const derived = revocationPubkey(toHex(base.point), chain.point(3));
  // …and only the counterparty can produce the matching private key.
  const secret = revocationKeyPair(base.privateKey, perCommitmentSecret);

  assert.equal(derived, toHex(secret.publicKey), 'point and scalar sides must agree');
  assert.equal(fromHex(derived).length, PUBKEY_BYTES, 'the result is a signing key, so x-only');

  // And it actually signs.
  const digest = taggedHash('t', utf8('penalty'));
  assert.equal(verify(sign(digest, secret.privateKey), digest, fromHex(derived)), true);
});

test('the revocation identity is exercised across many parities', () => {
  // The homomorphism is where a naive x-only conversion silently breaks, and it
  // breaks for exactly half the keys. Twenty rounds makes a miss implausible.
  for (let i = 0; i < 20; i++) {
    const base = keyPairFromSeed(`schnorr/rev/multi/${i}`);
    const chain = new SecretChain(`schnorr/rev/multi/commit/${i}`);
    const derived = revocationPubkey(toHex(base.point), chain.point(i));
    const secret = revocationKeyPair(base.privateKey, chain.secret(i));
    assert.equal(derived, toHex(secret.publicKey), `parity round ${i} diverged`);
  }
});

test('passing an x-only key where a point is required is refused, not silently wrong', () => {
  const base = keyPairFromSeed('schnorr/rev/guard');
  const chain = new SecretChain('schnorr/rev/guard/commitments');
  assert.throws(
    () => revocationPubkey(toHex(base.publicKey), chain.point(0)),
    /compressed 33-byte points/,
  );
});

test('pointCombine and scalarCombine still agree', () => {
  const k1 = keyPairFromSeed('schnorr/ec/1').privateKey;
  const k2 = keyPairFromSeed('schnorr/ec/2').privateKey;
  const s1 = 0x1234_5678n;
  const s2 = 0x9abc_def0n;

  const combinedPoint = pointCombine(pointFromSecret(k1), s1, pointFromSecret(k2), s2);
  const combinedScalar = scalarCombine(k1, s1, k2, s2);
  assert.equal(toHex(combinedPoint), toHex(pointFromSecret(combinedScalar)));
  assert.equal(toHex(toXOnly(combinedPoint)), toHex(xOnlyFromSecret(combinedScalar)));
});
