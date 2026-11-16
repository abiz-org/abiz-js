// SPDX-License-Identifier: Apache-2.0
// The resolution algorithm (IMPLEMENTING.md; SPEC.md §3, §4, §6), adapted from the
// ABIZ reference resolver (resolve.abizrecord.org) and free of I/O: DNS
// and HTTPS go through the Transport the caller supplies.
import { firstDuplicateMember } from './duplicates.js';
import { apexSuggestion, normaliseInput } from './host.js';
import { parseRecordJson } from './json.js';
import { verifySignature } from './signature.js';
import type { Transport } from './transport.js';
import { isAbizAssertion, isNearMissAssertion, parseAssertion, type AbizAssertion } from './txt.js';
import { linkChecks, MAX_PROBLEMS, semanticProblems, validateSchema, type Problem } from './validate.js';

export type ResolveStatus = 'resolved' | 'invalid_input' | 'not_found' | 'conflict' | 'invalid_record' | 'unavailable';

/** Stable error codes, the same as the hosted resolver's (resolve.abizrecord.org). */
export type ErrorCode =
  // invalid_input
  | 'missing_input'
  | 'both_inputs'
  | 'invalid_domain'
  | 'invalid_website'
  | 'non_public_domain'
  // not_found
  | 'missing_txt'
  // conflict
  | 'multiple_txt'
  // invalid_record: the DNS assertion
  | 'bad_pointer'
  | 'duplicate_tag'
  | 'missing_h'
  | 'unsafe_host'
  | 'invalid_key'
  // invalid_record: the record
  | 'fetch_failed'
  | 'record_too_large'
  | 'not_json'
  | 'schema_invalid'
  | 'identity_host_mismatch'
  | 'domain_not_claimed'
  | 'business_key_mismatch'
  | 'public_key_mismatch'
  | 'signature_invalid'
  // unavailable
  | 'dns_timeout'
  | 'dns_failure'
  | 'upstream_timeout'
  | 'origin_unavailable';

/** The codes {@link checkRecord} can return. */
export type RecordProblemCode =
  | 'bad_pointer'
  | 'duplicate_tag'
  | 'missing_h'
  | 'unsafe_host'
  | 'invalid_key'
  | 'record_too_large'
  | 'not_json'
  | 'schema_invalid'
  | 'identity_host_mismatch'
  | 'domain_not_claimed'
  | 'business_key_mismatch'
  | 'public_key_mismatch'
  | 'signature_invalid';

export interface Warning {
  code: 'content_type' | 'try_apex';
  message: string;
  /** For try_apex: the domain that might be checked instead. A suggestion; it was not checked. */
  domain?: string;
}

export interface Discovery {
  /** Where the assertion came from. */
  method: 'dns_txt' | 'well_known';
  /** The DNS name queried: `_abiz.<domain>`. */
  owner: string;
  /** The `v=abiz1` TXT value used, exactly as published. Absent when the well-known file supplied the assertion. */
  dns_value?: string;
  /** For a conflict: every `v=abiz1` value found. */
  dns_values?: string[];
  /** `https://<h>?format=json`, the address fetched. */
  record_url?: string;
  /**
   * `/.well-known/abiz.json`: `not_checked` when DNS answered with an assertion (or failed),
   * `used` when it supplied the assertion, `absent` or `invalid` when it was fetched and could not
   * be used, `unavailable` when its fetch failed (the result is then `unavailable`).
   */
  well_known: 'not_checked' | 'absent' | 'invalid' | 'unavailable' | 'used';
  /** Set when the well-known file was fetched. */
  well_known_url?: string;
}

export interface ResolveResult {
  status: ResolveStatus;
  /** Null when resolved. */
  code: ErrorCode | null;
  message: string;
  /** True when the same question may get a different answer later (DNS or origin failures). */
  retryable: boolean;
  /** Where in the assertion or record a problem is, for publisher errors. At most 25. */
  details: Problem[];
  /** True when more than 25 problems were found. */
  truncated: boolean;
  /** The input as given (a domain, or a website when no domain was given). */
  query: { domain?: string; website?: string };
  /** The normalised domain that was queried, or null when the input was refused. */
  domain: string | null;
  /** How the record was found. Absent when the input was refused. */
  discovery?: Discovery;
  /** The record exactly as published. Present only when status is `resolved`. */
  record?: Record<string, unknown>;
  warnings: Warning[];
}

export type ResolveInput = string | { domain?: string | null; website?: string | null };

export interface ResolveOptions {
  /** DNS and HTTPS. Required here; `abiz/node` and {@link dohTransport} provide ready-made ones. */
  transport: Transport;
}

const MESSAGES: Record<ErrorCode, string> = {
  missing_input: 'Give a domain (such as example.com) or a website address.',
  both_inputs: 'Give either a domain or a website, not both.',
  invalid_domain: 'The domain is not a valid public host name.',
  invalid_website: 'The website address is not valid.',
  non_public_domain: 'The domain is a special-use or private-network name.',
  missing_txt:
    'DNS answered and there is no v=abiz1 TXT record at this name, and /.well-known/abiz.json is missing or not usable, so the domain publishes no ABIZ record.',
  multiple_txt: 'More than one v=abiz1 TXT record is published at this name. The publisher must keep exactly one.',
  bad_pointer: 'The ABIZ TXT record is malformed.',
  duplicate_tag: 'The ABIZ TXT record repeats a tag.',
  missing_h: 'The ABIZ TXT record has no h= tag.',
  unsafe_host: 'The record host is not a public address this library will fetch.',
  invalid_key: 'The ABIZ TXT record has no p= key, or a p= value that is not an Ed25519 public key in standard base64 (44 characters ending in "=").',
  fetch_failed: 'The record host did not serve the record.',
  record_too_large: 'The record is larger (64 KiB) or more deeply nested (16 levels, 5,000 members) than ABIZ allows.',
  not_json: 'The record host did not answer with a JSON object (I-JSON, no repeated member names).',
  schema_invalid: 'The record does not conform to the ABIZ business record schema.',
  identity_host_mismatch: "The record's identity_host does not match the DNS h= value.",
  domain_not_claimed: "The record's domains list does not include the queried domain.",
  business_key_mismatch: "The business key in DNS and the record's registration fields disagree.",
  public_key_mismatch: "The record's public_key is not the Ed25519 key published as p= in DNS.",
  signature_invalid: "The record's signature is missing or does not verify with its public_key (Ed25519 over the RFC 8785 form of the record without signature).",
  dns_timeout: 'The ABIZ TXT lookup could not be completed. This does not establish that no ABIZ record exists.',
  dns_failure: 'The DNS resolver could not answer for this name (for example SERVFAIL). This does not establish that no ABIZ record exists.',
  upstream_timeout: 'The host did not answer in time. This does not establish that the record is missing.',
  origin_unavailable: 'The host is temporarily unavailable. This does not establish that the record is missing.',
};

const STATUS_OF: Record<ErrorCode, ResolveStatus> = {
  missing_input: 'invalid_input',
  both_inputs: 'invalid_input',
  invalid_domain: 'invalid_input',
  invalid_website: 'invalid_input',
  non_public_domain: 'invalid_input',
  missing_txt: 'not_found',
  multiple_txt: 'conflict',
  bad_pointer: 'invalid_record',
  duplicate_tag: 'invalid_record',
  missing_h: 'invalid_record',
  unsafe_host: 'invalid_record',
  invalid_key: 'invalid_record',
  fetch_failed: 'invalid_record',
  record_too_large: 'invalid_record',
  not_json: 'invalid_record',
  schema_invalid: 'invalid_record',
  identity_host_mismatch: 'invalid_record',
  domain_not_claimed: 'invalid_record',
  business_key_mismatch: 'invalid_record',
  public_key_mismatch: 'invalid_record',
  signature_invalid: 'invalid_record',
  dns_timeout: 'unavailable',
  dns_failure: 'unavailable',
  upstream_timeout: 'unavailable',
  origin_unavailable: 'unavailable',
};

const RETRYABLE: ReadonlySet<ErrorCode> = new Set(['dns_timeout', 'dns_failure', 'upstream_timeout', 'origin_unavailable']);

/** The status a code belongs to. */
export function statusOf(code: ErrorCode): ResolveStatus {
  return STATUS_OF[code];
}

/** SPEC.md §4.5. `h` has no query, so the JSON representation is this exact URL. */
export function recordUrl(h: string): string {
  return `https://${h}?format=json`;
}

/** SPEC.md §3.4.1. The file is on the queried domain, not on `h`. */
export function wellKnownUrl(domain: string): string {
  return `https://${domain}/.well-known/abiz.json`;
}

function isJsonType(contentType: string): boolean {
  const type = contentType.split(';', 1)[0]!.trim().toLowerCase();
  return type === 'application/json' || /^application\/[a-z0-9.+-]+\+json$/.test(type);
}

/** SPEC.md §3.4.2. Unknown members are ignored. The result is parsed as a DNS assertion. */
function assertionTextFromWellKnown(document: unknown): { ok: true; value: string } | { ok: false; message: string } {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    return { ok: false, message: 'The well-known file must be a JSON object.' };
  }
  const doc = document as Record<string, unknown>;
  for (const member of ['v', 'k', 'h', 'p']) {
    if (member in doc && typeof doc[member] !== 'string') return { ok: false, message: `Well-known member ${member} must be a string.` };
  }
  if (doc.v !== 'abiz1') return { ok: false, message: 'The well-known file must have "v": "abiz1".' };
  for (const member of ['h', 'p'] as const) {
    if (typeof doc[member] !== 'string') return { ok: false, message: `The well-known file is missing ${member}.` };
  }
  const parts = ['v=abiz1'];
  for (const member of ['k', 'h', 'p'] as const) {
    if (!(member in doc)) continue;
    const value = doc[member] as string;
    if (!value || /[\s;]/.test(value)) return { ok: false, message: `Well-known member ${member} must be a non-empty value without whitespace or ';'.` };
    parts.push(`${member}=${value}`);
  }
  return { ok: true, value: parts.join(';') };
}

type Evaluated = { ok: true; record: Record<string, unknown> } | { ok: false; code: RecordProblemCode; details: Problem[] };

/**
 * Steps 7–9 on a record's text: parse as I-JSON within limits, the schema and semantic checks, the
 * link to the assertion and the queried domain, then the signature. First failure wins.
 */
async function evaluateRecord(text: string, domain: string, assertion: AbizAssertion): Promise<Evaluated> {
  const json = parseRecordJson(text);
  if (!json.ok) return { ok: false, code: json.problem === 'invalid_json' ? 'not_json' : 'record_too_large', details: [] };
  // SPEC.md §4.6 (I-JSON): a repeated member name is rejected, never resolved by "last one wins".
  const duplicate = firstDuplicateMember(text);
  if (duplicate !== null) {
    return { ok: false, code: 'not_json', details: [{ path: duplicate || '$', message: 'The record repeats a member name; ABIZ records are I-JSON (RFC 7493).' }] };
  }
  const schemaProblems = validateSchema(json.value);
  if (schemaProblems.length) return { ok: false, code: 'schema_invalid', details: schemaProblems };
  const record = json.value as Record<string, unknown>;
  const semantic = semanticProblems(record);
  const link = linkChecks(record, domain, assertion);
  const keyProblems = [...semantic.businessKey, ...link.businessKey];
  if (semantic.conformance.length) return { ok: false, code: 'schema_invalid', details: [...semantic.conformance, ...keyProblems] };
  if (!link.identityHostMatches) {
    return { ok: false, code: 'identity_host_mismatch', details: [{ path: '/identity_host', message: `identity_host must equal the DNS h= value (${assertion.h}) exactly, path included.` }] };
  }
  if (!link.queriedDomainInRecord) {
    return { ok: false, code: 'domain_not_claimed', details: [{ path: '/domains', message: `domains must include ${domain}, the domain whose _abiz record points here.` }] };
  }
  if (keyProblems.length) return { ok: false, code: 'business_key_mismatch', details: keyProblems };
  const signed = await verifySignature(record, assertion.p);
  if (!signed.ok) return { ok: false, code: signed.code, details: [{ path: signed.path, message: signed.message }] };
  return { ok: true, record };
}

/** The record check's outcome with its details. */
export type RecordCheck = { ok: true; record: Record<string, unknown> } | { ok: false; code: RecordProblemCode; message: string; details: Problem[] };

/**
 * Check a record offline against the queried domain and the assertion (a `_abiz` TXT value or a
 * parsed assertion), with the reasons. Nothing is fetched.
 */
export async function checkRecordDetailed(recordText: string, domain: string, assertion: string | AbizAssertion): Promise<RecordCheck> {
  let parsed: AbizAssertion;
  if (typeof assertion === 'string') {
    const result = parseAssertion(assertion);
    if (!result.ok) return { ok: false, code: result.code, message: MESSAGES[result.code], details: [{ path: '$assertion', message: result.message }] };
    parsed = result.assertion;
  } else {
    parsed = assertion;
  }
  const out = await evaluateRecord(recordText, domain.toLowerCase().replace(/\.$/, ''), parsed);
  return out.ok ? out : { ...out, message: MESSAGES[out.code] };
}

/**
 * Check a record offline (test-vectors/records.json): null when it is accepted, else the first
 * failing code. `domain` is the queried domain; `assertion` the `_abiz` TXT value or a parsed one.
 */
export async function checkRecord(recordText: string, domain: string, assertion: string | AbizAssertion): Promise<RecordProblemCode | null> {
  const out = await checkRecordDetailed(recordText, domain, assertion);
  return out.ok ? null : out.code;
}

function capped(problems: Problem[] | undefined): { details: Problem[]; truncated: boolean } {
  const list = problems ?? [];
  return list.length > MAX_PROBLEMS ? { details: list.slice(0, MAX_PROBLEMS), truncated: true } : { details: list, truncated: false };
}

/**
 * Resolve a domain (or a website's host) to its checked ABIZ record. Only `_abiz.<domain>` is
 * queried; when it has no v=abiz1 value, `https://<domain>/.well-known/abiz.json` is fetched; then
 * the one record at `https://<h>?format=json`. Nothing else is fetched: an advertised
 * `mcp_server_url` or any other URL in the record is never contacted, and no company register is
 * consulted. A resolved record is the publisher's own claim, signed with the key DNS vouches for.
 */
export async function resolve(input: ResolveInput, options: ResolveOptions): Promise<ResolveResult> {
  const given = typeof input === 'string' ? { domain: input } : (input ?? {});
  const query: ResolveResult['query'] = {};
  const hasDomain = typeof given.domain === 'string' && given.domain !== '';
  if (typeof given.website === 'string' && given.website !== '' && !hasDomain) query.website = given.website;
  const normal = normaliseInput(given);
  if (!normal.ok) {
    if (hasDomain) query.domain = given.domain!;
    return {
      status: STATUS_OF[normal.problem],
      code: normal.problem,
      message: normal.message,
      retryable: false,
      details: [],
      truncated: false,
      query,
      domain: null,
      warnings: [],
    };
  }
  query.domain = normal.domain;
  return resolveDomain(normal.domain, query, options.transport);
}

async function resolveDomain(domain: string, query: ResolveResult['query'], transport: Transport): Promise<ResolveResult> {
  const owner = `_abiz.${domain}`;
  const discovery: Discovery = { method: 'dns_txt', owner, well_known: 'not_checked' };
  const warnings: Warning[] = [];
  const base = { query, domain, discovery, warnings };
  const fail = (code: ErrorCode, problems?: Problem[], message?: string): ResolveResult => ({
    status: STATUS_OF[code],
    code,
    message: message ?? MESSAGES[code],
    retryable: RETRYABLE.has(code),
    ...capped(problems),
    ...base,
  });

  // Step 2: one TXT query. A failure is never absence.
  const lookup = await transport.queryTxt(owner);
  if (lookup.kind === 'error') return fail(lookup.reason === 'timeout' || lookup.reason === 'network' ? 'dns_timeout' : 'dns_failure');

  // Step 3: select.
  const values = lookup.kind === 'answer' ? lookup.values : [];
  const matching = values.filter(isAbizAssertion);
  if (matching.length > 1) {
    discovery.dns_values = matching;
    return fail('multiple_txt');
  }

  let assertion: AbizAssertion;
  if (matching.length === 1) {
    // Step 4: a malformed assertion is invalid; the well-known file is not used.
    const value = matching[0]!;
    discovery.dns_value = value;
    const parsed = parseAssertion(value);
    if (!parsed.ok) return fail(parsed.code, [{ path: owner, message: parsed.message }]);
    assertion = parsed.assertion;
  } else if (values.some(isNearMissAssertion)) {
    return fail('bad_pointer', [{ path: owner, message: 'A TXT record looks like an ABIZ assertion, but its first tag is not exactly v=abiz1 (check case, spaces and quotes).' }]);
  } else {
    // Step 5: no v=abiz1 value; the well-known file may carry the same tags (SPEC.md §3.4).
    const fileUrl = wellKnownUrl(domain);
    discovery.well_known_url = fileUrl;
    const file = await transport.fetch(fileUrl);
    if (file.kind === 'timeout') {
      discovery.well_known = 'unavailable';
      return fail('upstream_timeout');
    }
    if (file.kind === 'network' || file.kind === 'dns_error') {
      discovery.well_known = 'unavailable';
      return fail('origin_unavailable', undefined, 'The well-known file could not be fetched. This does not establish that no ABIZ record exists.');
    }
    if (file.kind === 'response' && (file.status === 408 || file.status === 429 || file.status >= 500)) {
      discovery.well_known = 'unavailable';
      return fail('origin_unavailable', undefined, `The well-known file's host answered HTTP ${file.status}. This does not establish that no ABIZ record exists.`);
    }
    let fromFile: AbizAssertion | undefined;
    let invalidMessage: string | undefined;
    if (file.kind === 'response' && file.status === 200) {
      const type = file.contentType?.split(';', 1)[0]?.trim().toLowerCase() ?? '';
      if (file.body === null) invalidMessage = 'The well-known file is larger than 64 KiB.';
      else if (!isJsonType(type)) invalidMessage = 'The well-known file was not served as application/json.';
      else {
        const parsedJson = parseRecordJson(file.body);
        if (!parsedJson.ok) invalidMessage = 'The well-known file is not JSON.';
        else {
          const tags = assertionTextFromWellKnown(parsedJson.value);
          if (!tags.ok) invalidMessage = tags.message;
          else {
            const parsed = parseAssertion(tags.value);
            if (!parsed.ok) invalidMessage = parsed.message;
            else fromFile = parsed.assertion;
          }
        }
      }
    }
    if (!fromFile) {
      discovery.well_known = invalidMessage ? 'invalid' : 'absent';
      const apex = apexSuggestion(domain);
      if (apex) {
        warnings.push({
          code: 'try_apex',
          domain: apex,
          message: `Nothing is published at ${owner}. ${apex} was not checked and is a different domain; check it separately if it is the business's domain.`,
        });
      }
      return fail('missing_txt', invalidMessage ? [{ path: fileUrl, message: invalidMessage }] : undefined);
    }
    discovery.method = 'well_known';
    discovery.well_known = 'used';
    assertion = fromFile;
  }

  // Step 6: fetch the one record.
  const url = recordUrl(assertion.h);
  discovery.record_url = url;
  const fetched = await transport.fetch(url);
  switch (fetched.kind) {
    case 'blocked':
      return fail('unsafe_host', [{ path: 'h', message: fetched.message }]);
    case 'no_address':
      return fail('fetch_failed', [{ path: 'h', message: 'The record host has no public A or AAAA address.' }]);
    case 'dns_error':
      return fail('origin_unavailable', undefined, "The record host's address could not be looked up. This does not establish that the record is missing.");
    case 'timeout':
      return fail('upstream_timeout');
    case 'network':
      return fail('origin_unavailable', undefined, 'The connection to the record host failed (network or TLS). This does not establish that the record is missing.');
    case 'response':
      break;
  }
  const { status: httpStatus, contentType, body } = fetched;
  if (httpStatus === 408 || httpStatus === 429 || httpStatus >= 500) {
    return fail('origin_unavailable', undefined, `The record host answered HTTP ${httpStatus}. This does not establish that the record is missing.`);
  }
  if (httpStatus >= 300 && httpStatus < 400) {
    return fail('fetch_failed', [{ path: 'h', message: `The record host answered with a redirect (HTTP ${httpStatus}). Redirects are not followed: serve the record at the exact h= address.` }]);
  }
  if (httpStatus !== 200) return fail('fetch_failed', [{ path: 'h', message: `The record host answered HTTP ${httpStatus}; ABIZ needs 200 with the JSON record.` }]);
  if (body === null) return fail('record_too_large');
  if (contentType && !isJsonType(contentType)) {
    const type = contentType.split(';', 1)[0]!.trim().toLowerCase();
    if (type !== 'text/plain') return fail('not_json', [{ path: 'h', message: `The record host answered ${type.slice(0, 80)} to Accept: application/json.` }]);
  }
  if (!contentType || !isJsonType(contentType)) {
    warnings.push({ code: 'content_type', message: 'The record was served without a JSON content type; it was read as JSON anyway.' });
  }

  // Steps 7–9.
  const checked = await evaluateRecord(body, domain, assertion);
  if (!checked.ok) return fail(checked.code, checked.details);
  return {
    status: 'resolved',
    code: null,
    message: 'The record was found and passed every ABIZ check. Its contents are the publisher\'s own claim; no company register was consulted.',
    retryable: false,
    details: [],
    truncated: false,
    ...base,
    record: checked.record,
  };
}
