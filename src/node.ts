// SPDX-License-Identifier: Apache-2.0
// `abiz/node`: the Node.js transport, and `resolve` with it as the default.
//
// DNS: node:dns (c-ares), one try with a 2.5 s timeout; NXDOMAIN and NODATA are absence, every
// other failure is a failure. HTTPS: node:https with the fetch guard. The host's A and AAAA
// records are read, every address must be public unicast, and the connection is made to the
// checked address (a `lookup` that returns only that address), so there is no second DNS lookup
// to rebind. The TLS server name and Host header stay the host name and the certificate is
// verified against it. No redirects are followed, 5 s over the whole exchange, 64 KiB of decoded
// body at most.
import { Resolver } from 'node:dns/promises';
import { request, type RequestOptions } from 'node:https';
import type { IncomingMessage } from 'node:http';
import type { LookupFunction } from 'node:net';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import type { Readable } from 'node:stream';
import { MAX_RECORD_BYTES } from './json.js';
import { resolve as resolveWith, type ResolveInput, type ResolveResult } from './resolve.js';
import {
  DNS_TIMEOUT_MS,
  FETCH_TIMEOUT_MS,
  USER_AGENT,
  guardedFetch,
  type AddressLookup,
  type FetchOutcome,
  type Transport,
  type TxtLookup,
} from './transport.js';

export interface NodeTransportOptions {
  /** DNS servers for node:dns (`['1.1.1.1']`); the system's by default. */
  dnsServers?: string[];
  dnsTimeoutMs?: number;
  fetchTimeoutMs?: number;
  userAgent?: string;
  /** Replaces the A/AAAA lookup the guard uses (for tests, or a caching resolver). */
  lookupAddresses?: (host: string) => Promise<AddressLookup>;
}

function resolver(options: NodeTransportOptions): Resolver {
  const r = new Resolver({ timeout: options.dnsTimeoutMs ?? DNS_TIMEOUT_MS, tries: 1 });
  if (options.dnsServers?.length) r.setServers(options.dnsServers);
  return r;
}

function errorCode(err: unknown): string {
  return err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : '';
}

/** A TXT lookup with node:dns. Each record's character-strings are joined with nothing between them. */
export function nodeTxtLookup(options: NodeTransportOptions = {}): (name: string) => Promise<TxtLookup> {
  return async (name) => {
    try {
      const records = await resolver(options).resolveTxt(name);
      return records.length === 0 ? { kind: 'nodata' } : { kind: 'answer', values: records.map((chunks) => chunks.join('')) };
    } catch (err) {
      switch (errorCode(err)) {
        case 'ENOTFOUND':
          return { kind: 'nxdomain' };
        case 'ENODATA':
          return { kind: 'nodata' };
        case 'ETIMEOUT':
          return { kind: 'error', reason: 'timeout' };
        case 'ESERVFAIL':
          return { kind: 'error', reason: 'servfail' };
        case 'EREFUSED':
          return { kind: 'error', reason: 'refused' };
        case 'EFORMERR':
        case 'EBADRESP':
        case 'EBADNAME':
        case 'EBADQUERY':
          return { kind: 'error', reason: 'malformed' };
        default:
          return { kind: 'error', reason: 'network' };
      }
    }
  };
}

/** A and AAAA with node:dns, for the fetch guard. */
export function nodeAddressLookup(options: NodeTransportOptions = {}): (host: string) => Promise<AddressLookup> {
  return async (host) => {
    const r = resolver(options);
    const one = async (family: 4 | 6): Promise<string[] | null> => {
      try {
        return family === 4 ? await r.resolve4(host) : await r.resolve6(host);
      } catch (err) {
        const code = errorCode(err);
        return code === 'ENOTFOUND' || code === 'ENODATA' ? [] : null;
      }
    };
    const [v4, v6] = await Promise.all([one(4), one(6)]);
    if (v4 === null || v6 === null) return { kind: 'error' };
    return { kind: 'addresses', addresses: [...v4, ...v6].map((a) => a.toLowerCase()) };
  };
}

function decoded(res: IncomingMessage): Readable | null {
  const encoding = (res.headers['content-encoding'] ?? 'identity').toString().trim().toLowerCase();
  switch (encoding) {
    case '':
    case 'identity':
      return res;
    case 'gzip':
    case 'x-gzip':
      return res.pipe(createGunzip());
    case 'deflate':
      return res.pipe(createInflate());
    case 'br':
      return res.pipe(createBrotliDecompress());
    default:
      return null;
  }
}

/** One GET to `address`, presented to the server as `url`'s host. */
function connectPinned(url: URL, address: string, options: NodeTransportOptions): Promise<FetchOutcome> {
  return new Promise<FetchOutcome>((settle) => {
    let done = false;
    const finish = (outcome: FetchOutcome) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      settle(outcome);
    };
    const family = address.includes(':') ? 6 : 4;
    // Every lookup for this request answers with the checked address: no second DNS query.
    const lookup = ((_host: string, opts: { all?: boolean }, cb: (...args: unknown[]) => void) => {
      if (opts && opts.all) cb(null, [{ address, family }]);
      else cb(null, address, family);
    }) as unknown as LookupFunction;
    const requestOptions: RequestOptions = {
      method: 'GET',
      host: url.hostname,
      servername: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      headers: { accept: 'application/json', 'accept-encoding': 'identity', 'user-agent': options.userAgent ?? USER_AGENT },
      lookup,
      agent: false,
      rejectUnauthorized: true,
    };
    const req = request(requestOptions, (res) => {
      const status = res.statusCode ?? 0;
      const header = res.headers['content-type'];
      const contentType = typeof header === 'string' ? header : null;
      if (status !== 200) {
        res.destroy();
        finish({ kind: 'response', status, contentType, body: '' });
        return;
      }
      const declared = res.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/.test(declared.trim()) || Number(declared) > MAX_RECORD_BYTES)) {
        res.destroy();
        finish({ kind: 'response', status: 200, contentType, body: null });
        return;
      }
      const stream = decoded(res);
      if (!stream) {
        res.destroy();
        finish({ kind: 'network' });
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      stream.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RECORD_BYTES) {
          res.destroy();
          stream.destroy();
          finish({ kind: 'response', status: 200, contentType, body: null });
          return;
        }
        chunks.push(chunk);
      });
      stream.on('end', () => finish({ kind: 'response', status: 200, contentType, body: new TextDecoder().decode(Buffer.concat(chunks)) }));
      stream.on('error', () => finish({ kind: 'network' }));
      // A body cut short ends with 'close' and no 'end'.
      stream.on('close', () => finish({ kind: 'network' }));
      res.on('error', () => finish({ kind: 'network' }));
    });
    const timer = setTimeout(() => {
      finish({ kind: 'timeout' });
      req.destroy();
    }, options.fetchTimeoutMs ?? FETCH_TIMEOUT_MS);
    req.on('error', () => finish({ kind: 'network' }));
    req.end();
  });
}

/** The guarded record fetch over node:https, connected to the checked address. */
export function nodeFetch(options: NodeTransportOptions = {}): (url: string) => Promise<FetchOutcome> {
  const lookup = options.lookupAddresses ?? nodeAddressLookup(options);
  return (rawUrl) => guardedFetch(rawUrl, lookup, (url, address) => connectPinned(url, address, options));
}

/** node:dns plus node:https with the address pinned. */
export function nodeTransport(options: NodeTransportOptions = {}): Transport {
  return { queryTxt: nodeTxtLookup(options), fetch: nodeFetch(options) };
}

/** {@link resolveWith | resolve} with the Node transport unless another is given. */
export function resolve(input: ResolveInput, options: { transport?: Transport } = {}): Promise<ResolveResult> {
  return resolveWith(input, { transport: options.transport ?? nodeTransport() });
}

export * from './index.js';
