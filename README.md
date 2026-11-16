# abiz

The consumer side of [ABIZ](https://abizrecord.org) (Agentic Business Record) 1.1 for JavaScript and TypeScript. Given a domain, it finds the domain's `_abiz` DNS TXT record, fetches the signed business record that record points to, and checks it. It returns the same status and error code as the hosted resolver at `resolve.abizrecord.org`.

ESM only. Node 20 or later, Deno, Cloudflare Workers and browsers (the offline functions everywhere; network resolution where the platform allows it, see [Transports](#transports)).

## Install

```bash
npm install @abiz-org/abiz
```

## Example

```js
import { resolve } from '@abiz-org/abiz/node';

const result = await resolve('example.com'); // or resolve({ website: 'https://www.example.com/contact' })
// On Workers, Deno or in a browser: import { resolve, dohTransport } from '@abiz-org/abiz'
// and call resolve('example.com', { transport: dohTransport() }).

if (result.status === 'resolved') {
  console.log(result.record.business_name); // the publisher's own claim, signed with the key DNS vouches for
} else {
  console.log(result.status, result.code, result.message, result.details);
}
```

From the command line:

```bash
npx abiz check example.com
npx abiz check example.com --json
```

`abiz check` exits with 0 when the record resolved, 1 for any other result and 2 for a usage error.

## What is checked, and what is not

Checked, in this order, the first failure deciding the result:

1. The input: a domain or a website's host, lower case, IDN to A-labels, one trailing dot dropped. A URL, port, credentials or IP literal is refused, and so is a special-use or private-network name. `www.` is never stripped; when nothing is found at a `www.` name the result suggests the apex as a warning, without checking it.
2. One TXT query for `_abiz.<domain>`. A DNS failure is reported as `unavailable`, never as "no record".
3. Exactly one value starting with `v=abiz1`; its tags (`v`, `h`, `k`, `p`) parsed strictly (SPEC §3).
4. Only when DNS answered with no `v=abiz1` value: `https://<domain>/.well-known/abiz.json` (SPEC §3.4).
5. One GET of `https://<h>?format=json`, through the fetch guard: HTTPS only, every resolved address public, no redirects followed, 5 seconds, 64 KiB.
6. The record as I-JSON (no repeated member names, nesting at most 16, at most 5,000 members), the ABIZ 1.1 JSON Schema (Draft 2020-12, formats asserted) and the checks the schema cannot express (country and region codes, URLs, opening hours, unique ids, ratings and others).
7. `identity_host` equals `h`; `domains` includes the queried domain; `k`, if present, equals `business_key`, which agrees with `country` and `registration_number`.
8. `public_key` equals the DNS `p`, and `signature` is a valid Ed25519 signature by that key over the RFC 8785 (JCS) form of the record without its `signature`.

Not checked:

- **No company register is consulted.** A registration number or business key in a record is what the publisher says, not a confirmed registration.
- **`mcp_server_url` is never called**, and no other URL in the record is fetched. At most two requests are made: the well-known file (only when DNS has no assertion) and the record.
- A resolved record is the publisher's own claim, signed with the key that the domain's DNS vouches for. It shows that whoever controls the domain's DNS published this record. It does not show that the business facts in it are true. This library says "checked", not "verified", for that reason.
- DNSSEC is not validated.

## Transports

Resolution needs a TXT lookup and an HTTPS fetch. Both sit behind one small interface, `Transport` (`queryTxt(name)` and `fetch(url)`), so you can supply your own (a cache, a proxy, a different DNS service) and so the test vectors run against stubs.

- **`abiz/node`** uses `node:dns` for TXT, A and AAAA, and `node:https` for the fetch. It refuses unless every address of the host is public, then connects to the address it checked (the TLS server name and `Host` stay the host name, and the certificate is verified against it). There is no second DNS lookup between the check and the connection.
- **`dohTransport()`** in `abiz` uses DNS-over-HTTPS (Cloudflare's `https://cloudflare-dns.com/dns-query` by default; pass `endpoint` to change it) and the platform's `fetch`. It applies the same checks before fetching, but **a platform `fetch` cannot be told which address to connect to**, so it cannot close the window between the check and the connection (DNS rebinding). On Cloudflare Workers outbound requests cannot reach private addresses anyway. Elsewhere, pass your own `fetch` with egress controls, or use `abiz/node`. In a browser the record host must also allow the request under CORS, which most do not.

The `User-Agent` is `abiz-js/2026.1116.1 (+https://abizrecord.org)` where the platform lets it be set.

## API

All exported from `@abiz-org/abiz` (and re-exported from `@abiz-org/abiz/node`).

| Function | Returns |
| --- | --- |
| `resolve(domain \| { domain } \| { website }, { transport })` | `Promise<ResolveResult>`: `status` (`resolved`, `invalid_input`, `not_found`, `conflict`, `invalid_record`, `unavailable`), `code` (null when resolved), `message`, `retryable`, `details` (path and message, at most 25), `truncated`, `query`, `domain`, `record` (only when resolved), `discovery` (`method` `dns_txt` or `well_known`, `owner`, `dns_value`, `record_url`, `well_known`), `warnings` (`content_type`, `try_apex` with `domain`). In `abiz/node` the transport defaults to the Node one. |
| `parseAssertion(value)` | `{ ok: true, assertion: { h, k?, p, unknown } }` or `{ ok: false, code, message }` |
| `checkRecord(recordText, domain, assertion)` | `Promise<null \| code>`, offline. `checkRecordDetailed` adds the details. |
| `verifySignature(record, p)` | `Promise<{ ok: true } \| { ok: false, code: 'public_key_mismatch' \| 'signature_invalid', … }>` |
| `canonicalize(value)` | The RFC 8785 text |
| `signRecord(record, seed)` | `Promise` of the record with `public_key` and `signature` set (a producer helper; `seed` is the 32-byte Ed25519 private key as bytes or hex) |
| `dohTransport(options)`, `nodeTransport(options)` (`abiz/node`) | A `Transport` |
| `isPublicAddress(address)`, `normaliseInput(input)`, `identityParts(value)`, `isAbizPublicKey(value)`, `parseBusinessKey(value)`, `guardedFetch(url, lookup, connect)` | The building blocks, for custom transports |

The bundled files are importable too: `abiz/schema/abiz-business-record-v1.1.schema.json`, `abiz/schema/abiz-well-known-v1.1.schema.json` and `abiz/schema/iso3166.json`.

## Conformance

Implements ABIZ 1.1. Passes every case of the shared ABIZ test vectors, format 1 (`assertions`, `public-keys`, `hosts`, `addresses`, `jcs`, `signing`, `records` and `resolution`), run with `npm test`. The bundled schema and country list are pinned by SHA-256:

| File | SHA-256 |
| --- | --- |
| `schema/abiz-business-record-v1.1.schema.json` | `3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24` |
| `schema/abiz-well-known-v1.1.schema.json` | `5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741` |
| `schema/iso3166.json` | `0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527` |

Dependencies: [`@cfworker/json-schema`](https://www.npmjs.com/package/@cfworker/json-schema) (JSON Schema 2020-12) and [`@noble/ed25519`](https://www.npmjs.com/package/@noble/ed25519) (Ed25519, RFC 8032 verification rules). JCS is implemented in this package.

## Licence

Apache-2.0 (`LICENSE`, `NOTICE`). `schema/iso3166.json` is not covered by the Apache licence: it is extracted from the Debian iso-codes data and distributed under the GNU Lesser General Public License, version 2.1 (see `NOTICE` and `schema/ISO3166-README.md`).

Never sign a real record with the test keys in the test vectors: their private seeds are public.
