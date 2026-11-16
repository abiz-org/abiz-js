// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// Host names: the queried domain, a website's host, the `h=` record host and the URLs a record
// carries. The rules follow the ABIZ reference validator (scripts/validate.py: safe_host,
// identity_parts, check_https), plus the input rules of the resolver spec (§4 step 1).

const HOST = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const IPV4ISH = /^[0-9.]+$/;

/**
 * Suffixes that never name a public business domain: special-use names (RFC 6761, RFC 6762,
 * RFC 7686, RFC 8375, RFC 9476) and the private names people use on internal networks. A query
 * for one is refused before any DNS is sent.
 */
const NON_PUBLIC_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'invalid',
  'test',
  'example',
  'onion',
  'arpa',
  'alt',
  'lan',
  'home',
  'corp',
  'intranet',
  'private',
];

/** A DNS host name as the reference validator accepts it (lower case, dotted, no IP literal). */
export function isSafeHost(raw: string): boolean {
  const value = raw.toLowerCase().replace(/\.$/, '');
  if (!HOST.test(value) || value.includes('..') || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  if (labels.some((label) => label.length === 0 || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return false;
  if (IPV4ISH.test(value)) return false;
  return true;
}

/** True when the host ends in a special-use or private-network suffix. */
export function isNonPublicHost(host: string): boolean {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  const tld = labels.at(-1) ?? '';
  if (NON_PUBLIC_SUFFIXES.includes(tld)) return true;
  // A top-level label is never all digits; xn-- labels are fine.
  if (/^[0-9]+$/.test(tld)) return true;
  return false;
}

export type InputProblem = 'missing_input' | 'both_inputs' | 'invalid_domain' | 'invalid_website' | 'non_public_domain';

export type NormalisedInput = { ok: true; domain: string; from: 'domain' | 'website' } | { ok: false; problem: InputProblem; message: string };

const DOMAIN_FORBIDDEN = /[\s/?#@:\\%[\]"'<>`{}|^]/;

/**
 * A queried domain, normalised: lower case, IDN to Punycode (A-labels), one trailing dot dropped.
 * A host only: a URL, a port, credentials or an IP literal is refused. `www.example.com` stays
 * `www.example.com`; it is never replaced by the apex.
 */
export function normaliseDomain(raw: string): NormalisedInput {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, problem: 'invalid_domain', message: 'The domain is empty.' };
  if (trimmed.length > 254) return { ok: false, problem: 'invalid_domain', message: 'The domain is longer than 253 characters.' };
  if (DOMAIN_FORBIDDEN.test(trimmed)) {
    return { ok: false, problem: 'invalid_domain', message: 'Give a host name such as example.com, not a URL. To pass a website address, use the website parameter.' };
  }
  return hostToDomain(trimmed, 'domain');
}

/** The host of a website address (http or https), normalised as {@link normaliseDomain}. The path is ignored. */
export function domainFromWebsite(raw: string): NormalisedInput {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, problem: 'invalid_website', message: 'The website is empty.' };
  if (trimmed.length > 2048) return { ok: false, problem: 'invalid_website', message: 'The website address is longer than 2048 characters.' };
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, problem: 'invalid_website', message: 'The website is not a valid URL.' };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, problem: 'invalid_website', message: 'Only http and https website addresses are accepted.' };
  }
  if (url.username || url.password) {
    return { ok: false, problem: 'invalid_website', message: 'A website address with a user name or password is refused.' };
  }
  const host = url.hostname;
  if (host.startsWith('[')) return { ok: false, problem: 'invalid_website', message: 'An IP address is not a business domain.' };
  const out = hostToDomain(host, 'website');
  if (!out.ok && out.problem === 'invalid_domain') return { ok: false, problem: 'invalid_website', message: out.message };
  return out;
}

/** Exactly one of `domain` and `website`, normalised to a domain. */
export function normaliseInput(input: { domain?: string | null; website?: string | null }): NormalisedInput {
  const hasDomain = typeof input.domain === 'string' && input.domain !== '';
  const hasWebsite = typeof input.website === 'string' && input.website !== '';
  if (hasDomain && hasWebsite) return { ok: false, problem: 'both_inputs', message: 'Give either domain or website, not both.' };
  if (hasDomain) return normaliseDomain(input.domain!);
  if (hasWebsite) return domainFromWebsite(input.website!);
  return { ok: false, problem: 'missing_input', message: 'Give a domain (such as example.com) or a website address.' };
}

function hostToDomain(raw: string, from: 'domain' | 'website'): NormalisedInput {
  let host = raw.replace(/\.$/, '');
  // IDN to A-labels through the URL parser (UTS #46), which also lower-cases.
  try {
    host = new URL(`https://${host}/`).hostname;
  } catch {
    return { ok: false, problem: 'invalid_domain', message: 'The domain is not a valid host name.' };
  }
  host = host.replace(/\.$/, '');
  if (host.startsWith('[') || IPV4ISH.test(host)) return { ok: false, problem: 'invalid_domain', message: 'An IP address is not a business domain.' };
  if (!isSafeHost(host)) return { ok: false, problem: 'invalid_domain', message: 'The domain is not a valid public host name.' };
  if (isNonPublicHost(host)) {
    return { ok: false, problem: 'non_public_domain', message: 'The domain ends in a special-use or private-network name, so it has no public ABIZ record.' };
  }
  return { ok: true, domain: host, from };
}

/** The parent of a `www.` host, offered as a suggestion only (never resolved in its place). */
export function apexSuggestion(domain: string): string | null {
  if (!domain.startsWith('www.')) return null;
  const rest = domain.slice(4);
  return isSafeHost(rest) ? rest : null;
}

const PATH = /^\/[\x21-\x7e]*$/;

/**
 * An `h=` value or an `identity_host`: a host name with an optional path, never a scheme,
 * credentials, port, query or fragment, and no `.` or `..` path segment. Returns the canonical
 * form (host lower case, path as written) or null. Compared exactly, path included.
 */
export function identityParts(value: string): string | null {
  if (!value || value.includes('://') || /[?#@\s\\]/.test(value)) return null;
  const slash = value.indexOf('/');
  const host = (slash === -1 ? value : value.slice(0, slash)).toLowerCase();
  const path = slash === -1 ? '' : value.slice(slash);
  if (host.includes(':')) return null;
  if (!isSafeHost(host)) return null;
  if (path) {
    if (!PATH.test(path)) return null;
    if (path.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  }
  return host.replace(/\.$/, '') + path;
}

/** The host part of an identity value. */
export function identityHostname(identity: string): string {
  const slash = identity.indexOf('/');
  return slash === -1 ? identity : identity.slice(0, slash);
}

/**
 * The special-use and private-use names SPEC.md §4.7.1 rules out of a record's URLs (RFC 6761,
 * RFC 6762, RFC 7686, RFC 8375, RFC 9476 and ICANN's .internal), as the reference validator's
 * public_dns_host does. The documentation names `.example` and `.test` stay accepted so that
 * examples validate; the resolver's own stricter list ({@link isNonPublicHost}) is for what it queries and fetches.
 */
const SPEC_NON_PUBLIC_SUFFIXES = ['localhost', 'local', 'internal', 'home.arpa', 'onion', 'invalid', 'alt'];

/** True when the host is a special-use or private-use name under SPEC.md §4.7.1. */
export function isSpecialUseName(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  return SPEC_NON_PUBLIC_SUFFIXES.some((suffix) => name === suffix || name.endsWith(`.${suffix}`));
}

/**
 * An https URL with a public DNS host name (no IP literal, no special-use or private-use name), no
 * credentials, no fragment and the default port (SPEC.md §4.7.1; the reference check_url). These
 * URLs are reported, never fetched.
 */
export function isSafeHttpsUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port) return false;
  if (url.hostname.startsWith('[')) return false;
  return isSafeHost(url.hostname) && !isSpecialUseName(url.hostname);
}
