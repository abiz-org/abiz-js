// Every case in the shared test vectors (test-vectors/, format 1).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  canonicalize,
  checkRecord,
  identityParts,
  isAbizAssertion,
  isAbizPublicKey,
  isPublicAddress,
  normaliseInput,
  parseAssertion,
  publicKeyFromSeed,
  resolve,
  signingInput,
  signRecord,
  verifySignature,
  type FetchOutcome,
  type Transport,
  type TxtLookup,
} from '../src/index.js';

const DIR = fileURLToPath(new URL('../test-vectors/', import.meta.url));
/* eslint-disable @typescript-eslint/no-explicit-any */
const table = (list: any[], name: (c: any) => string): Array<[string, any]> => list.map((c) => [name(c), c]);
const load = (name: string): any => {
  const data = JSON.parse(readFileSync(`${DIR}${name}`, 'utf8'));
  expect(data.format).toBe(1);
  return data;
};

describe('assertions.json', () => {
  const { cases } = load('assertions.json');
  it.each(table(cases, (c: { name: string }) => c.name))('%s', (_name, c: Record<string, unknown>) => {
    expect(isAbizAssertion(c.value as string)).toBe(c.is_assertion);
    const parsed = parseAssertion(c.value as string);
    expect(parsed.ok).toBe(c.ok);
    if (parsed.ok) {
      expect(parsed.assertion.h).toBe(c.h);
      expect(parsed.assertion.p).toBe(c.p);
      expect(parsed.assertion.k).toBe(c.k);
    } else {
      expect(parsed.code).toBe(c.code);
    }
  });
});

describe('public-keys.json', () => {
  const { cases } = load('public-keys.json');
  it.each(table(cases, (c: { value: string }) => JSON.stringify(c.value)))('%s', (_n, c: { value: string; ok: boolean }) => {
    expect(isAbizPublicKey(c.value)).toBe(c.ok);
  });
});

describe('hosts.json', () => {
  const data = load('hosts.json');
  it.each(table(data.identity, (c: { value: string }) => c.value))('identity %s', (_n, c: { value: string; canonical: string | null }) => {
    expect(identityParts(c.value)).toBe(c.canonical);
  });
  it.each(table(data.inputs, (c: { input: unknown }) => JSON.stringify(c.input)))('input %s', (_n, c: { input: { domain?: string; website?: string }; ok: boolean; domain?: string; code?: string }) => {
    const r = normaliseInput(c.input);
    expect(r.ok).toBe(c.ok);
    if (r.ok) expect(r.domain).toBe(c.domain);
    else expect(r.problem).toBe(c.code);
  });
});

describe('addresses.json', () => {
  const { cases } = load('addresses.json');
  it.each(table(cases, (c: { address: string }) => c.address))('%s', (_n, c: { address: string; public: boolean }) => {
    expect(isPublicAddress(c.address)).toBe(c.public);
  });
});

describe('jcs.json', () => {
  const { cases } = load('jcs.json');
  it.each(table(cases, (c: { name: string }) => c.name))('%s', (_n, c: { input: string; output: string }) => {
    expect(canonicalize(JSON.parse(c.input))).toBe(c.output);
  });
});

describe('signing.json', () => {
  const data = load('signing.json');
  it.each(table(data.cases, (c: { name: string }) => c.name))('%s', async (_n, c: { record_text: string; signing_input: string; verifies: boolean }) => {
    const record = JSON.parse(c.record_text) as Record<string, unknown>;
    expect(new TextDecoder().decode(signingInput(record))).toBe(c.signing_input);
    const check = await verifySignature(record, record.public_key as string);
    expect(check.ok).toBe(c.verifies);
  });
  it.each(table(data.test_keys, (k: { name: string }) => k.name))('%s derives its public key and signs reproducibly', async (_n, k: { seed_hex: string; public_key: string }) => {
    expect(await publicKeyFromSeed(k.seed_hex)).toBe(k.public_key);
    const sample = { record_version: 'abiz1', note: 'not a record; a signing test' };
    const signed = await signRecord(sample, k.seed_hex);
    expect(signed.public_key).toBe(k.public_key);
    expect((await verifySignature(signed, k.public_key)).ok).toBe(true);
  });
  it('signRecord reproduces the "test key 1 sample" case byte for byte', async () => {
    const sampleCase = data.cases.find((c: { name: string }) => c.name === 'test key 1 sample');
    const signed = await signRecord({ record_version: 'abiz1', note: 'not a record; a signing test' }, data.test_keys[0].seed_hex);
    expect(JSON.stringify(signed)).toBe(sampleCase.record_text);
  });
});

describe('records.json', () => {
  const { cases } = load('records.json');
  it.each(table(cases, (c: { name: string }) => c.name))('%s', async (_n, c: { record_text: string; domain: string; assertion: string; expect: string | null }) => {
    expect(await checkRecord(c.record_text, c.domain, c.assertion)).toBe(c.expect);
  });
});

type DnsStub = { kind: 'answer'; values: string[] } | { kind: 'nxdomain' | 'nodata' } | { kind: 'error'; reason: 'timeout' | 'network' | 'servfail' | 'refused' | 'malformed' };
type HttpStub = { kind: 'response'; status: number; content_type: string | null; body: string | null } | { kind: 'blocked' | 'no_address' | 'dns_error' | 'timeout' | 'network' };

describe('resolution.json', () => {
  const { cases } = load('resolution.json');
  it.each(table(cases, (c: { name: string }) => c.name))('%s', async (_n, c: { input: Record<string, string>; dns: Record<string, DnsStub>; http: Record<string, HttpStub>; expect: Record<string, unknown> }) => {
    const queried: string[] = [];
    const fetched: string[] = [];
    const transport: Transport = {
      async queryTxt(name): Promise<TxtLookup> {
        queried.push(name);
        const stub = c.dns[name] ?? { kind: 'nxdomain' };
        if (stub.kind === 'answer') return { kind: 'answer', values: stub.values };
        if (stub.kind === 'error') return { kind: 'error', reason: stub.reason };
        return { kind: stub.kind };
      },
      async fetch(url): Promise<FetchOutcome> {
        fetched.push(url);
        const stub = c.http[url] ?? { kind: 'response', status: 404, content_type: 'text/plain', body: 'Not found' };
        if (stub.kind === 'response') return { kind: 'response', status: stub.status, contentType: stub.content_type, body: stub.body };
        if (stub.kind === 'blocked') return { kind: 'blocked', message: 'stub: refused address' };
        return { kind: stub.kind };
      },
    };
    const r = await resolve(c.input, { transport });
    const e = c.expect;
    expect(r.status).toBe(e.status);
    expect(r.code).toBe(e.code);
    expect(r.retryable).toBe(e.retryable);
    expect(r.discovery?.method).toBe(e.method);
    expect(r.discovery?.well_known).toBe(e.well_known);
    expect(r.discovery?.dns_value).toBe(e.dns_value);
    expect(r.query.domain).toBe(e.domain);
    expect(r.warnings.map((w) => (w.domain ? { code: w.code, domain: w.domain } : { code: w.code }))).toEqual(e.warnings);
    expect(r.record !== undefined).toBe(e.record_returned);
    expect(queried).toEqual(e.dns_queries);
    expect(fetched).toEqual(e.fetches);
  });
});
