// SPDX-License-Identifier: Apache-2.0
// A transport for any runtime with fetch: DNS-over-HTTPS (JSON API) for TXT and address lookups,
// and the platform's fetch for HTTPS.
//
// Limit, stated plainly: the platform's fetch does its own DNS lookup when it connects, and a web
// fetch has no way to connect to a given address. The guard here resolves the host over DoH and
// refuses unless every address is public, but it cannot pin the connection to the address it
// checked, so a host whose DNS answer changes between the check and the connection (DNS
// rebinding) is not stopped by this library. On Cloudflare Workers, outbound fetch cannot reach
// private or loopback addresses whatever the name resolves to; elsewhere, supply `fetch` with
// your own egress controls, or use the Node transport (`abiz/node`), which pins the address.
import { decodeTxtData } from './txt.js';
import { MAX_RECORD_BYTES } from './json.js';
import {
  DNS_TIMEOUT_MS,
  FETCH_TIMEOUT_MS,
  USER_AGENT,
  guardedFetch,
  readCappedStream,
  type AddressLookup,
  type FetchOutcome,
  type Transport,
  type TxtLookup,
} from './transport.js';

/** Cloudflare's DNS-over-HTTPS JSON endpoint (the 1.1.1.1 resolver). */
export const DEFAULT_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

export interface DohOptions {
  /** A DNS-over-HTTPS endpoint that speaks the JSON API (`?name=…&type=TXT`, `application/dns-json`). */
  endpoint?: string;
  /** The fetch used for DoH queries and for the record. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Per DNS query, in milliseconds. Default 2,500. */
  dnsTimeoutMs?: number;
  /** For the whole record fetch, in milliseconds. Default 5,000. */
  fetchTimeoutMs?: number;
  /** Sent where the platform allows it (browsers do not). */
  userAgent?: string;
}

type DohAnswer = { Status?: unknown; Answer?: unknown };
type DohResult = { kind: 'ok'; json: DohAnswer } | { kind: 'timeout' } | { kind: 'network' } | { kind: 'malformed' };

function fetchImpl(options: DohOptions): typeof fetch {
  const impl = options.fetch ?? globalThis.fetch;
  if (typeof impl !== 'function') throw new TypeError('No fetch is available: pass options.fetch.');
  return impl;
}

async function dohQuery(name: string, type: 'TXT' | 'A' | 'AAAA', options: DohOptions): Promise<DohResult> {
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.dnsTimeoutMs ?? DNS_TIMEOUT_MS);
  try {
    const res = await fetchImpl(options)(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      return { kind: 'network' };
    }
    const bytes = await readCappedStream(res.body, 65_536);
    if (bytes === null) return { kind: 'malformed' };
    const json = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (!json || typeof json !== 'object' || typeof (json as DohAnswer).Status !== 'number') return { kind: 'malformed' };
    return { kind: 'ok', json: json as DohAnswer };
  } catch (err) {
    if (err instanceof SyntaxError) return { kind: 'malformed' };
    return { kind: controller.signal.aborted ? 'timeout' : 'network' };
  } finally {
    clearTimeout(timer);
  }
}

function rows(section: unknown): Array<{ type: number; data: string }> {
  if (!Array.isArray(section)) return [];
  const out: Array<{ type: number; data: string }> = [];
  for (const row of section) {
    if (!row || typeof row !== 'object') continue;
    const { type, data } = row as { type?: unknown; data?: unknown };
    if (typeof type === 'number' && typeof data === 'string') out.push({ type, data });
  }
  return out;
}

/** A TXT lookup over DNS-over-HTTPS. Quoted character-strings are joined and unescaped. */
export function dohTxtLookup(options: DohOptions = {}): (name: string) => Promise<TxtLookup> {
  return async (name) => {
    const r = await dohQuery(name, 'TXT', options);
    if (r.kind !== 'ok') return { kind: 'error', reason: r.kind === 'malformed' ? 'malformed' : r.kind };
    switch (r.json.Status) {
      case 0: {
        const txt = rows(r.json.Answer).filter((row) => row.type === 16);
        return txt.length === 0 ? { kind: 'nodata' } : { kind: 'answer', values: txt.map((row) => decodeTxtData(row.data)) };
      }
      case 3:
        return { kind: 'nxdomain' };
      case 2:
        return { kind: 'error', reason: 'servfail' };
      case 5:
        return { kind: 'error', reason: 'refused' };
      default:
        return { kind: 'error', reason: 'malformed' };
    }
  };
}

/** A and AAAA over DNS-over-HTTPS, for the fetch guard. */
export function dohAddressLookup(options: DohOptions = {}): (host: string) => Promise<AddressLookup> {
  return async (host) => {
    const [v4, v6] = await Promise.all([dohQuery(host, 'A', options), dohQuery(host, 'AAAA', options)]);
    const out: string[] = [];
    for (const r of [v4, v6]) {
      if (r.kind !== 'ok') return { kind: 'error' };
      if (r.json.Status !== 0 && r.json.Status !== 3) return { kind: 'error' };
      for (const row of rows(r.json.Answer)) if (row.type === 1 || row.type === 28) out.push(row.data.toLowerCase());
    }
    return { kind: 'addresses', addresses: out };
  };
}

/**
 * The record fetch with the platform's fetch: the guard's checks, then one GET with
 * `redirect: 'manual'`, 5 s over the whole exchange and a 64 KiB cap on the decoded body. The
 * connection is not pinned to the checked address (see the top of this file).
 */
export function platformFetch(options: DohOptions = {}): (url: string) => Promise<FetchOutcome> {
  const lookup = dohAddressLookup(options);
  return (rawUrl) =>
    guardedFetch(rawUrl, lookup, async (url) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), options.fetchTimeoutMs ?? FETCH_TIMEOUT_MS);
      try {
        const res = await fetchImpl(options)(url.href, {
          method: 'GET',
          redirect: 'manual',
          headers: { accept: 'application/json', 'user-agent': options.userAgent ?? USER_AGENT },
          signal: controller.signal,
        });
        const contentType = res.headers.get('content-type');
        // A browser reports a manual redirect as an opaque response with status 0: not a 200.
        if (res.status !== 200) {
          await res.body?.cancel().catch(() => undefined);
          return { kind: 'response', status: res.type === 'opaqueredirect' ? 302 : res.status, contentType, body: '' };
        }
        const declared = res.headers.get('content-length');
        if (declared !== null && (!/^\d+$/.test(declared.trim()) || Number(declared) > MAX_RECORD_BYTES)) {
          await res.body?.cancel().catch(() => undefined);
          return { kind: 'response', status: 200, contentType, body: null };
        }
        const bytes = await readCappedStream(res.body, MAX_RECORD_BYTES);
        return { kind: 'response', status: 200, contentType, body: bytes === null ? null : new TextDecoder().decode(bytes) };
      } catch {
        return { kind: controller.signal.aborted ? 'timeout' : 'network' };
      } finally {
        clearTimeout(timer);
      }
    });
}

/** DNS-over-HTTPS plus the platform's fetch: works on Node 20+, Deno, Cloudflare Workers and browsers. */
export function dohTransport(options: DohOptions = {}): Transport {
  return { queryTxt: dohTxtLookup(options), fetch: platformFetch(options) };
}
