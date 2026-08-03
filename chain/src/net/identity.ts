/**
 * Node identity.
 *
 * Encryption alone stops a passive observer. It does nothing about an active
 * man-in-the-middle, who simply runs two sessions — one with each side — and
 * relays between them, reading everything. The ECDH in `transport.ts` cannot
 * prevent that, because neither ephemeral key is tied to anybody.
 *
 * ── The fix: sign the transcript ──────────────────────────────────────────
 * Each node holds a long-term Schnorr identity key. Immediately after the key
 * exchange, each side sends
 *
 *     identity ‖ Schnorr(identitySecret, H("auth", network, sessionId))
 *
 * `sessionId` is derived from *both* ephemeral keys, so it is different on the
 * two legs of a relayed connection. An attacker in the middle therefore
 * receives a signature valid for the session it shares with Alice, and needs a
 * different one for the session it shares with Bob — which it cannot produce
 * without Bob's identity key. The relay is detected at the first frame.
 *
 * This is the SIGMA pattern, and it is the same reason SSH signs its exchange
 * hash rather than just performing a key exchange.
 *
 * ── Trust on first use ────────────────────────────────────────────────────
 * A signature proves *someone* owns a key. Whether that key is the one you
 * meant to talk to is a separate question, and it has no cryptographic answer
 * without prior knowledge. Two mechanisms are provided:
 *
 *   • **Pinning.** `--connect host:port#identity` states the expected key up
 *     front. A mismatch aborts the connection. This is the strong form.
 *   • **Trust on first use.** The first identity seen for an address is
 *     recorded; a later change is reported loudly. This is what SSH does, and
 *     it detects an attacker who was not present at first contact.
 *
 * TOFU is genuinely weaker than pinning and is not pretended otherwise — an
 * adversary present from the very first connection is not detected by it.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import {
  fromHex,
  keyFromSeed,
  keyPair,
  randomPrivateKey,
  sign,
  taggedHash,
  toHex,
  utf8,
  verify,
  type Hex,
  type KeyPair,
} from '../crypto.ts';
import type { ChainStore } from '../store/sqlite.ts';

export interface AuthPayload {
  /** 32-byte x-only identity key, hex. */
  readonly identity: Hex;
  /** Schnorr signature over the session digest. */
  readonly signature: Hex;
}

/**
 * What both sides sign.
 *
 * Binds the network name as well as the session, so a signature captured on
 * testnet can never authenticate a mainnet connection even if an attacker
 * could somehow replay the same session id.
 */
export function authDigest(network: string, sessionId: Hex): Uint8Array {
  return taggedHash('DeckxCoin/net/auth/v1', utf8(network), fromHex(sessionId));
}

export function signAuth(identity: KeyPair, network: string, sessionId: Hex): AuthPayload {
  return {
    identity: toHex(identity.publicKey),
    signature: sign(authDigest(network, sessionId), identity.privateKey),
  };
}

/**
 * Check a peer's proof of identity.
 *
 * Returns the identity on success. A failure here is always fatal: it means
 * either a bug, or somebody sitting between the two nodes.
 */
export function checkAuth(
  payload: AuthPayload | undefined,
  network: string,
  sessionId: Hex,
): { ok: boolean; identity?: Hex; error?: string } {
  if (!payload || typeof payload.identity !== 'string' || typeof payload.signature !== 'string') {
    return { ok: false, error: 'version message carried no identity proof' };
  }

  let identityBytes: Uint8Array;
  try {
    identityBytes = fromHex(payload.identity);
  } catch {
    return { ok: false, error: 'identity is not hex' };
  }
  if (identityBytes.length !== 32) {
    return { ok: false, error: `identity must be 32 bytes, got ${identityBytes.length}` };
  }

  if (!verify(payload.signature, authDigest(network, sessionId), identityBytes)) {
    return {
      ok: false,
      error: 'identity proof does not match this session — a relay is sitting in the middle',
    };
  }
  return { ok: true, identity: payload.identity };
}

/* ─────────────────────────────────────────────────── persistent key ── */

/**
 * Load the node's identity, generating one on first run.
 *
 * Stored as a bare hex secret in the datadir. That is exactly as safe as the
 * datadir itself, which is the same assumption the block database already
 * makes — an attacker who can read `chain.sqlite` can rewrite the node's view
 * of the chain anyway.
 */
export function loadIdentity(path: string): KeyPair {
  try {
    const raw = readFileSync(path, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(raw)) return keyPair(fromHex(raw));
  } catch {
    // Missing or unreadable: fall through and mint a new one.
  }

  const secret = randomPrivateKey();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, toHex(secret), { encoding: 'utf8', mode: 0o600 });
  return keyPair(secret);
}

/** Deterministic identity, for tests and reproducible local networks. */
export const identityFromSeed = (seed: string): KeyPair => keyPair(keyFromSeed(seed));

/* ────────────────────────────────────────────────────────── pinning ── */

/** `host:port#identity` — the strong form, where the key is known in advance. */
export interface PeerAddress {
  readonly host: string;
  readonly port: number;
  readonly identity?: Hex;
}

export function parsePeerAddress(value: string, defaultPort: number): PeerAddress {
  const [hostPort, identity] = value.split('#', 2);
  const idx = hostPort.lastIndexOf(':');
  const host = idx === -1 ? hostPort : hostPort.slice(0, idx);
  const port = idx === -1 ? defaultPort : Number(hostPort.slice(idx + 1)) || defaultPort;

  if (identity !== undefined && !/^[0-9a-f]{64}$/.test(identity)) {
    throw new Error(`pinned identity must be 64 hex characters, got '${identity}'`);
  }
  return { host, port, identity };
}

export const KNOWN_IDENTITY_PREFIX = 'identity:';

export const IDENTITY_VERDICT = {
  /** First time this address has been seen. Recorded. */
  NEW: 'new',
  /** Matches what was recorded before. */
  KNOWN: 'known',
  /** Differs from what was recorded. Somebody is in the middle, or the peer re-keyed. */
  CHANGED: 'changed',
  /** Matches an explicitly pinned key. */
  PINNED: 'pinned',
  /** Does not match an explicitly pinned key. Always fatal. */
  MISMATCH: 'mismatch',
} as const;

export type IdentityVerdict = (typeof IDENTITY_VERDICT)[keyof typeof IDENTITY_VERDICT];

/**
 * Compare a peer's proven identity against what we expected.
 *
 * `expected` is a pin, when one was supplied. Otherwise the store's
 * trust-on-first-use record decides.
 */
export function judgeIdentity(
  store: ChainStore,
  host: string,
  port: number,
  identity: Hex,
  expected?: Hex,
): { verdict: IdentityVerdict; previous?: Hex } {
  if (expected) {
    return { verdict: expected === identity ? IDENTITY_VERDICT.PINNED : IDENTITY_VERDICT.MISMATCH, previous: expected };
  }

  const key = `${KNOWN_IDENTITY_PREFIX}${host}:${port}`;
  const previous = store.getMeta(key);

  if (previous === undefined) {
    store.setMeta(key, identity);
    return { verdict: IDENTITY_VERDICT.NEW };
  }
  if (previous === identity) return { verdict: IDENTITY_VERDICT.KNOWN, previous };
  return { verdict: IDENTITY_VERDICT.CHANGED, previous };
}

/**
 * Forget a remembered identity, so the next connection re-learns it.
 *
 * The operator's escape hatch when a peer legitimately re-keys. Deletes the
 * row rather than blanking it — a row holding an empty string still reads as
 * "we have seen an identity here", and the next connection would be reported
 * as a change rather than as new.
 */
export function forgetIdentity(store: ChainStore, host: string, port: number): boolean {
  return store.deleteMeta(`${KNOWN_IDENTITY_PREFIX}${host}:${port}`);
}

/** A verdict that must abort the connection. */
export const isFatalVerdict = (verdict: IdentityVerdict): boolean =>
  verdict === IDENTITY_VERDICT.MISMATCH || verdict === IDENTITY_VERDICT.CHANGED;
