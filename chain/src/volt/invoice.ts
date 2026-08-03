/**
 * Volt — invoices.
 *
 * A BOLT-11-shaped payment request: bech32m over a fixed binary layout,
 * signed by the payee's node key. The payer learns the payment hash, the
 * amount, the expiry and who to pay, and can verify all four came from the
 * payee without contacting them.
 *
 * Differences from BOLT-11, and why:
 *  • bech32m rather than bech32 — no legacy checksum to remain compatible with.
 *  • Fixed layout rather than tagged TLV fields. Every field is mandatory in
 *    Volt, so the tag machinery would encode nothing.
 *  • No route hints yet. Private-channel routing is a v0.2 feature; a payer
 *    that cannot find a public path today simply fails, rather than being
 *    handed a hint format that will change.
 *
 * BOLT-12 offers — reusable, static, no round trip to the payee — are the
 * right long-term shape, and the payload here is deliberately field-compatible
 * so an offer can wrap it later without a new invoice format.
 */

import { bech32m } from '@scure/base';
import {
  beBytes,
  beToBigInt,
  concat,
  fromHex,
  keyPair,
  randomPrivateKey,
  sha256,
  sign,
  taggedHash,
  toHex,
  utf8,
  verify,
  type Hex,
  type KeyPair,
} from '../crypto.ts';

export const INVOICE_HRP = 'lnvolt';
export const INVOICE_VERSION = 1;
/** Default validity window. Short on purpose: a stale payment hash is a liability. */
export const DEFAULT_EXPIRY_SECONDS = 3600;
/** Blocks of headroom the final hop demands before it will accept the HTLC. */
export const MIN_FINAL_CLTV = 18;

export interface Invoice {
  readonly version: number;
  /** Zaps. Zero means "any amount" — a donation request. */
  readonly amount: bigint;
  /** Unix seconds when the invoice was created. */
  readonly timestamp: number;
  readonly expirySeconds: number;
  readonly minFinalCltv: number;
  readonly paymentHash: Hex;
  readonly payee: Hex;
  /** SHA256 of the human-readable description. Keeps the invoice short. */
  readonly descriptionHash: Hex;
  readonly signature: Hex;
}

export interface PaymentSecret {
  readonly preimage: Hex;
  readonly paymentHash: Hex;
}

/** Generate a fresh preimage/hash pair. The preimage is the receipt. */
export function newPaymentSecret(): PaymentSecret {
  const preimage = randomPrivateKey();
  return { preimage: toHex(preimage), paymentHash: toHex(sha256(preimage)) };
}

/** Deterministic variant, so demos and tests produce reproducible invoices. */
export function paymentSecretFromSeed(seed: string): PaymentSecret {
  const preimage = taggedHash('Volt/preimage', utf8(seed));
  return { preimage: toHex(preimage), paymentHash: toHex(sha256(preimage)) };
}

/* --------------------------------------------------------------- encoding */

const BODY_SIZE = 1 + 8 + 8 + 4 + 4 + 32 + 32 + 32; // 121 — payee is x-only

function encodeBody(inv: Omit<Invoice, 'signature'>): Uint8Array {
  return concat(
    Uint8Array.of(inv.version),
    beBytes(inv.amount, 8),
    beBytes(BigInt(inv.timestamp), 8),
    beBytes(BigInt(inv.expirySeconds), 4),
    beBytes(BigInt(inv.minFinalCltv), 4),
    fromHex(inv.paymentHash),
    fromHex(inv.payee),
    fromHex(inv.descriptionHash),
  );
}

function decodeBody(b: Uint8Array): Omit<Invoice, 'signature'> {
  if (b.length !== BODY_SIZE) throw new Error(`decodeBody: expected ${BODY_SIZE} bytes, got ${b.length}`);
  return {
    version: b[0],
    amount: beToBigInt(b.subarray(1, 9)),
    timestamp: Number(beToBigInt(b.subarray(9, 17))),
    expirySeconds: Number(beToBigInt(b.subarray(17, 21))),
    minFinalCltv: Number(beToBigInt(b.subarray(21, 25))),
    paymentHash: toHex(b.subarray(25, 57)),
    payee: toHex(b.subarray(57, 89)),
    descriptionHash: toHex(b.subarray(89, 121)),
  };
}

const signingDigest = (body: Uint8Array): Uint8Array => taggedHash('Volt/invoice', body);

/* ------------------------------------------------------------- lifecycle */

export function createInvoice(opts: {
  payee: KeyPair;
  amount: bigint;
  paymentHash: Hex;
  description: string;
  timestamp?: number;
  expirySeconds?: number;
  minFinalCltv?: number;
}): Invoice {
  const unsigned: Omit<Invoice, 'signature'> = {
    version: INVOICE_VERSION,
    amount: opts.amount,
    timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
    expirySeconds: opts.expirySeconds ?? DEFAULT_EXPIRY_SECONDS,
    minFinalCltv: opts.minFinalCltv ?? MIN_FINAL_CLTV,
    paymentHash: opts.paymentHash,
    payee: toHex(opts.payee.publicKey),
    descriptionHash: toHex(sha256(utf8(opts.description))),
  };
  const signature = sign(signingDigest(encodeBody(unsigned)), opts.payee.privateKey);
  return { ...unsigned, signature };
}

/** Serialise to a `lnvolt1…` string. */
export function encodeInvoice(inv: Invoice): string {
  const payload = concat(encodeBody(inv), fromHex(inv.signature));
  return bech32m.encode(INVOICE_HRP, bech32m.toWords(payload), 1023);
}

export function decodeInvoice(encoded: string): Invoice {
  const { prefix, words } = bech32m.decode(encoded as `${string}1${string}`, 1023);
  if (prefix !== INVOICE_HRP) throw new Error(`decodeInvoice: wrong prefix ${prefix}`);
  const payload = Uint8Array.from(bech32m.fromWords(words));
  const body = decodeBody(payload.subarray(0, BODY_SIZE));
  return { ...body, signature: toHex(payload.subarray(BODY_SIZE)) };
}

/**
 * Verify signature and expiry.
 *
 * A payer must run this before paying. An unverified invoice is an
 * instruction from an unauthenticated source to lock up funds against a hash
 * only someone else knows the preimage to.
 */
export function checkInvoice(
  inv: Invoice,
  now: number = Math.floor(Date.now() / 1000),
): { ok: boolean; error?: string } {
  if (inv.version !== INVOICE_VERSION) return { ok: false, error: `unsupported version ${inv.version}` };
  const body = encodeBody(inv);
  if (!verify(inv.signature, signingDigest(body), fromHex(inv.payee))) {
    return { ok: false, error: 'invalid payee signature' };
  }
  if (now > inv.timestamp + inv.expirySeconds) {
    return { ok: false, error: `invoice expired at ${inv.timestamp + inv.expirySeconds}` };
  }
  if (now + 1 < inv.timestamp) return { ok: false, error: 'invoice timestamp is in the future' };
  return { ok: true };
}

/** Confirm a preimage really settles this invoice. The proof-of-payment check. */
export function isReceiptFor(inv: Invoice, preimage: Hex): boolean {
  return toHex(sha256(fromHex(preimage))) === inv.paymentHash;
}

export const payeeKeyPair = keyPair;
