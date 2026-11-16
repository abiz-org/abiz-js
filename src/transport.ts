// SPDX-License-Identifier: Apache-2.0
// The two ports resolution needs, and the fetch guard both network adapters share.
//
// A TXT lookup and a fetch, each with the outcomes test-vectors/resolution.json uses, so the
// algorithm runs against stubs and a caller can supply DNS-over-HTTPS, a proxy or a cache.
import { isNonPublicHost } from './host.js';
import { isPublicAddress } from './address.js';

export const DNS_TIMEOUT_MS = 2_500;
export const FETCH_TIMEOUT_MS = 5_000;
export const LIBRARY_VERSION = '2026.1116.1';
export const USER_AGENT = `abiz-js/${LIBRARY_VERSION} (+https://abizrecord.org)`;

/**
 * A TXT query's outcome. Absence (`nxdomain`, `nodata`) and failure (`error`) stay different:
 * a failure is never treated as absence. `values` are the record values with each record's
 * character-strings joined with nothing between them (already decoded, not quoted).
 */
export type TxtLookup =
  | { kind: 'answer'; values: string[] }
  | { kind: 'nxdomain' }
  | { kind: 'nodata' }
  | { kind: 'error'; reason: 'timeout' | 'network' | 'servfail' | 'refused' | 'malformed' };

/**
 * Fetching one URL. `body` is the decoded text, or null when the body was larger than 64 KiB.
 * `blocked`: the fetch guard refused the host. `no_address`: the name has no A or AAAA record.
 * `dns_error`: the address lookup failed. `timeout`: no complete answer within 5 s.
 * `network`: a connection or TLS failure.
 */
export type FetchOutcome =
  | { kind: 'response'; status: number; contentType: string | null; body: string | null }
  | { kind: 'blocked'; message: string }
  | { kind: 'no_address' }
  | { kind: 'dns_error' }
  | { kind: 'timeout' }
  | { kind: 'network' };

export interface Transport {
  /** TXT records at `name`. */
  queryTxt(name: string): Promise<TxtLookup>;
  /**
   * GET `url` with `Accept: application/json`: HTTPS only, no redirects followed, 5 s, 64 KiB,
   * and the fetch guard (every resolved address public) applied before connecting.
   */
  fetch(url: string): Promise<FetchOutcome>;
}

/** An A/AAAA lookup for the fetch guard. `addresses` is empty when the name has none (NXDOMAIN or NODATA). */
export type AddressLookup = { kind: 'addresses'; addresses: string[] } | { kind: 'error' };

/**
 * The fetch guard (SPEC.md §9), independent of how the request is made: refuse a URL that is not
 * https on the default port, carries credentials, or names an IP literal, a single label or a
 * special-use or private-network name; resolve the host; refuse unless every address is public
 * unicast; then call `connect` with the URL and one checked address. A `connect` that can pin the
 * connection to that address (the Node adapter does) leaves no DNS rebinding window; one that
 * cannot (a platform fetch) does, and says so in its documentation.
 */
export async function guardedFetch(
  rawUrl: string,
  lookupAddresses: (host: string) => Promise<AddressLookup>,
  connect: (url: URL, address: string) => Promise<FetchOutcome>,
): Promise<FetchOutcome> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { kind: 'blocked', message: 'The address is not a valid URL.' };
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port) {
    return { kind: 'blocked', message: 'Only https on the default port is fetched.' };
  }
  const host = url.hostname;
  if (host.startsWith('[') || /^[0-9.]+$/.test(host) || !host.includes('.') || isNonPublicHost(host) || host.endsWith('.localdomain')) {
    return { kind: 'blocked', message: 'The host is an IP address, a single label, or a special-use or private-network name.' };
  }
  const lookup = await lookupAddresses(host);
  if (lookup.kind === 'error') return { kind: 'dns_error' };
  if (lookup.addresses.length === 0) return { kind: 'no_address' };
  if (!lookup.addresses.every(isPublicAddress)) {
    return { kind: 'blocked', message: 'The host resolves to a private, reserved or special-purpose address.' };
  }
  return connect(url, lookup.addresses[0]!);
}

/** Read at most `max` bytes of a web stream; null when it is longer (the read is cancelled). */
export async function readCappedStream(body: ReadableStream<Uint8Array> | null, max: number): Promise<Uint8Array | null> {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}
