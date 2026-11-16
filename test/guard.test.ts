// The fetch guard and the network adapters, against stubs (no network).
import { describe, expect, it } from 'vitest';
import { checkRecord, dohTransport, guardedFetch, resolve, type AddressLookup, type FetchOutcome } from '../src/index.js';
import { nodeFetch } from '../src/node.js';

const ok = (): Promise<FetchOutcome> => Promise.resolve({ kind: 'response', status: 200, contentType: 'application/json', body: '{}' });
const addresses = (list: string[]) => async (): Promise<AddressLookup> => ({ kind: 'addresses', addresses: list });

describe('guardedFetch', () => {
  it('connects to a checked public address', async () => {
    let used = '';
    const out = await guardedFetch('https://records.example.org/a?format=json', addresses(['93.184.215.14']), async (_url, address) => {
      used = address;
      return ok();
    });
    expect(out.kind).toBe('response');
    expect(used).toBe('93.184.215.14');
  });

  it.each([['10.0.0.1'], ['127.0.0.1'], ['169.254.169.254'], ['::1'], ['fd00::1'], ['::ffff:10.0.0.1']])('refuses a host that resolves to %s', async (address) => {
    let connected = false;
    const out = await guardedFetch('https://records.example.org/', addresses(['8.8.8.8', address]), async () => {
      connected = true;
      return ok();
    });
    expect(out.kind).toBe('blocked');
    expect(connected).toBe(false);
  });

  it.each([
    ['http://records.example.org/'],
    ['https://records.example.org:8443/'],
    ['https://user:pw@records.example.org/'],
    ['https://192.0.2.1/'],
    ['https://[2001:db8::1]/'],
    ['https://intranet/'],
    ['https://printer.local/'],
    ['https://svc.internal/'],
  ])('refuses %s before any lookup', async (url) => {
    let looked = false;
    const out = await guardedFetch(url, async () => {
      looked = true;
      return { kind: 'addresses', addresses: ['8.8.8.8'] };
    }, ok);
    expect(out.kind).toBe('blocked');
    expect(looked).toBe(false);
  });

  it('reports no address and a failed lookup', async () => {
    expect((await guardedFetch('https://records.example.org/', addresses([]), ok)).kind).toBe('no_address');
    expect((await guardedFetch('https://records.example.org/', async () => ({ kind: 'error' }), ok)).kind).toBe('dns_error');
  });

  it('the Node fetch refuses a special-use name before any lookup', async () => {
    expect((await nodeFetch()('https://records.invalid/')).kind).toBe('blocked');
  });

  it('the Node fetch refuses a host whose stubbed lookup gives a private address, without connecting', async () => {
    // The stub answers for a name that does not exist, so a connection attempt could only fail
    // as `network` or `timeout`: `blocked` shows none was made.
    const fetchRecord = nodeFetch({ lookupAddresses: addresses(['203.0.113.9', '10.20.30.40']), fetchTimeoutMs: 1000 });
    expect(await fetchRecord('https://no-such-host.abiz-test.example.com/x?format=json')).toMatchObject({ kind: 'blocked' });
  });
});

describe('dohTransport (stubbed fetch)', () => {
  const doh = (answers: Record<string, unknown>, record?: Response) =>
    dohTransport({
      fetch: (async (input: RequestInfo | URL) => {
        const url = new URL(String(input));
        if (url.hostname === 'cloudflare-dns.com') {
          const key = `${url.searchParams.get('name')}/${url.searchParams.get('type')}`;
          const body = answers[key] ?? { Status: 3 };
          return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/dns-json' } });
        }
        return record ?? new Response('{}', { headers: { 'content-type': 'application/json' } });
      }) as typeof fetch,
    });

  it('joins and unescapes quoted TXT strings', async () => {
    const t = doh({ '_abiz.example.org/TXT': { Status: 0, Answer: [{ type: 16, data: '"v=abiz1;h=rec" "ords.example.org;p=x"' }] } });
    expect(await t.queryTxt('_abiz.example.org')).toEqual({ kind: 'answer', values: ['v=abiz1;h=records.example.org;p=x'] });
  });

  it('keeps NXDOMAIN, NODATA and SERVFAIL apart', async () => {
    const t = doh({ 'a.example.org/TXT': { Status: 0, Answer: [] }, 'b.example.org/TXT': { Status: 2 } });
    expect(await t.queryTxt('a.example.org')).toEqual({ kind: 'nodata' });
    expect(await t.queryTxt('b.example.org')).toEqual({ kind: 'error', reason: 'servfail' });
    expect(await t.queryTxt('c.example.org')).toEqual({ kind: 'nxdomain' });
  });

  it('refuses a record host that resolves to a private address', async () => {
    const t = doh({ 'records.example.org/A': { Status: 0, Answer: [{ type: 1, data: '192.168.1.10' }] }, 'records.example.org/AAAA': { Status: 0 } });
    expect((await t.fetch('https://records.example.org/x?format=json')).kind).toBe('blocked');
  });

  it('reads a record from a public host and reports redirects without following them', async () => {
    const answers = { 'records.example.org/A': { Status: 0, Answer: [{ type: 1, data: '93.184.215.14' }] }, 'records.example.org/AAAA': { Status: 0 } };
    const got = await doh(answers).fetch('https://records.example.org/x?format=json');
    expect(got).toEqual({ kind: 'response', status: 200, contentType: 'application/json', body: '{}' });
    const redirected = await doh(answers, new Response(null, { status: 302, headers: { location: 'https://elsewhere.example.org/' } })).fetch('https://records.example.org/x');
    expect(redirected).toMatchObject({ kind: 'response', status: 302 });
  });

  it('caps the body at 64 KiB', async () => {
    const answers = { 'records.example.org/A': { Status: 0, Answer: [{ type: 1, data: '93.184.215.14' }] }, 'records.example.org/AAAA': { Status: 0 } };
    const big = new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(70_000)); c.close(); } }), { headers: { 'content-type': 'application/json' } });
    expect(await doh(answers, big).fetch('https://records.example.org/x')).toMatchObject({ kind: 'response', status: 200, body: null });
  });

  it('a whole resolve over the stubbed DoH transport reports a refused address as unsafe_host', async () => {
    const t = doh({
      '_abiz.shop.example.com/TXT': { Status: 0, Answer: [{ type: 16, data: '"v=abiz1;h=records.example.com;p=VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc="' }] },
      'records.example.com/A': { Status: 0, Answer: [{ type: 1, data: '127.0.0.1' }] },
      'records.example.com/AAAA': { Status: 0 },
    });
    const r = await resolve('shop.example.com', { transport: t });
    expect(r).toMatchObject({ status: 'invalid_record', code: 'unsafe_host' });
  });
});

describe('record limits', () => {
  const assertion = 'v=abiz1;h=records.example.org;p=VWQYaWGhH5gcAwj/7ee6AnHsL1xzNlr4QdScICqIgjc=';
  it('refuses nesting deeper than 16', async () => {
    expect(await checkRecord(`${'['.repeat(17)}${']'.repeat(17)}`, 'example.org', assertion)).toBe('record_too_large');
  });
  it('refuses more than 5,000 members', async () => {
    const members = Array.from({ length: 5001 }, (_, i) => `"m${i}":0`).join(',');
    expect(await checkRecord(`{${members}}`, 'example.org', assertion)).toBe('record_too_large');
  });
});
