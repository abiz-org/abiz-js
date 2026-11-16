// SPDX-License-Identifier: Apache-2.0
// The record's own proof (SPEC.md §4.6): `public_key` must equal the DNS `p=`, and `signature` must
// be a valid Ed25519 (PureEd25519, RFC 8032) signature by that key over the UTF-8 bytes of the
// RFC 8785 (JCS) form of the record with only its top-level `signature` member removed (a
// `signature` inside an extension is signed). `public_key` and `p` are compared as exact strings.
//
// Ed25519 is @noble/ed25519's async API (SHA-512 from WebCrypto), which runs on Node 20+, Deno,
// Cloudflare Workers and browsers. Verification uses RFC 8032's strict rules (zip215: false).
import { getPublicKeyAsync, signAsync, verifyAsync } from '@noble/ed25519';
import { canonicalJson, JcsError } from './jcs.js';

/** Standard base64 of exactly 64 bytes. */
const SIGNATURE = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
/** Standard base64 of exactly 32 bytes. */
const PUBLIC_KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

export function base64ToBytes(text: string): Uint8Array {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
}

/** The bytes `signature` signs: JCS of the record without its top-level `signature`, as UTF-8. Throws JcsError for non-I-JSON. */
export function signingInput(record: Readonly<Record<string, unknown>>): Uint8Array {
  const rest: Record<string, unknown> = { ...record };
  delete rest.signature;
  return new TextEncoder().encode(canonicalJson(rest));
}

export type SignatureCheck =
  | { ok: true }
  | { ok: false; code: 'public_key_mismatch' | 'signature_invalid'; message: string; path: string };

/**
 * Check a record against the DNS assertion's `p`: `public_key` equal to `p`, then the signature.
 * A missing `p` counts as a mismatch: the record names a key DNS does not vouch for.
 */
export async function verifySignature(record: Readonly<Record<string, unknown>>, p: string | undefined): Promise<SignatureCheck> {
  const publicKey = record.public_key;
  const signature = record.signature;
  if (typeof publicKey !== 'string' || !PUBLIC_KEY.test(publicKey) || publicKey !== p) {
    return {
      ok: false,
      code: 'public_key_mismatch',
      path: '/public_key',
      message: p ? 'public_key must equal the DNS p= value exactly.' : 'The DNS assertion has no p= key, so the record public_key is not vouched for.',
    };
  }
  if (typeof signature !== 'string' || !SIGNATURE.test(signature)) {
    return { ok: false, code: 'signature_invalid', path: '/signature', message: 'signature must be 64 bytes of Ed25519 signature in standard base64.' };
  }
  let data: Uint8Array;
  try {
    data = signingInput(record);
  } catch (err) {
    if (err instanceof JcsError) return { ok: false, code: 'signature_invalid', path: '$', message: `The record cannot be canonicalised (RFC 8785): ${err.message}.` };
    throw err;
  }
  let valid = false;
  try {
    valid = await verifyAsync(base64ToBytes(signature), data, base64ToBytes(publicKey), { zip215: false });
  } catch {
    valid = false;
  }
  return valid
    ? { ok: true }
    : { ok: false, code: 'signature_invalid', path: '/signature', message: 'signature does not verify with public_key over the RFC 8785 form of the record without signature.' };
}

function seedBytes(privateKey: Uint8Array | string): Uint8Array {
  if (typeof privateKey === 'string') {
    if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) throw new TypeError('privateKey must be a 32-byte Ed25519 seed (64 hex characters or a Uint8Array).');
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) out[i] = parseInt(privateKey.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new TypeError('privateKey must be a 32-byte Ed25519 seed.');
  return privateKey;
}

/** The standard base64 Ed25519 public key (the value for `p=` and `public_key`) of a 32-byte seed. */
export async function publicKeyFromSeed(privateKey: Uint8Array | string): Promise<string> {
  return bytesToBase64(await getPublicKeyAsync(seedBytes(privateKey)));
}

/**
 * A producer helper: the record with `public_key` set to the seed's public key and `signature`
 * set to the Ed25519 signature over the JCS form of everything else. The input is not modified.
 * It signs whatever it is given: check the result with checkRecord before publishing it.
 */
export async function signRecord(record: Readonly<Record<string, unknown>>, privateKey: Uint8Array | string): Promise<Record<string, unknown>> {
  const seed = seedBytes(privateKey);
  const out: Record<string, unknown> = { ...record, public_key: bytesToBase64(await getPublicKeyAsync(seed)) };
  delete out.signature;
  out.signature = bytesToBase64(await signAsync(new TextEncoder().encode(canonicalJson(out)), seed));
  return out;
}
