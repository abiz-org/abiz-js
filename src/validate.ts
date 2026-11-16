// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// Record conformance (SPEC.md §4, §4.4, §4.7.13) and the cross-source checks (§6 steps 6–7).
// Updated for ABIZ 1.1: nested location addresses, plus the checks JSON Schema cannot express
// (unsupported country, time zones, overlapping hours, repeated ids, ratings within their scale).
//
// Structure: the pinned Draft 2020-12 schema, with `format` asserted.
// Semantics: assigned country codes on nested address.country.code, basic geo ranges.
import { Validator } from '@cfworker/json-schema';
import { countrySupportProblem, isAssignedCountry, parseBusinessKey, regionCodeProblem, sameBusinessKey } from './businessKey.js';
import { identityParts, isSafeHost, isSafeHttpsUrl } from './host.js';
import { ABIZ_SCHEMA } from './schema.js';
import type { AbizAssertion } from './txt.js';

export interface Problem {
  /** JSON Pointer into the record, or `$` for the whole record. */
  path: string;
  message: string;
}

export const MAX_PROBLEMS = 25;

let validator: Validator | undefined;
function schemaValidator(): Validator {
  validator ??= new Validator(ABIZ_SCHEMA as never, '2020-12', false);
  return validator;
}

function pointer(instanceLocation: string): string {
  const p = instanceLocation.replace(/^#/, '');
  return p === '' ? '$' : p;
}

export function validateSchema(record: unknown): Problem[] {
  const result = schemaValidator().validate(record as never);
  if (result.valid) return [];
  const seen = new Set<string>();
  const out: Problem[] = [];
  for (const error of result.errors) {
    if (error.keyword === 'properties' || error.keyword === 'items' || error.keyword === '$ref') continue;
    const problem = { path: pointer(error.instanceLocation), message: error.error.slice(0, 300) };
    const key = `${problem.path}\n${problem.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(problem);
  }
  return out.length ? out : [{ path: '$', message: 'The record does not match the ABIZ schema.' }];
}

type Rec = Record<string, unknown>;

function nestedCountryCode(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const code = (value as Rec).code;
  return typeof code === 'string' ? code : null;
}

const DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];

let ianaZones: ReadonlySet<string> | undefined;
function knownTimeZones(): ReadonlySet<string> {
  if (!ianaZones) {
    try {
      ianaZones = new Set(Intl.supportedValuesOf('timeZone'));
    } catch {
      ianaZones = new Set();
    }
  }
  return ianaZones;
}

function countryCodeProblem(code: string): string | null {
  if (!isAssignedCountry(code)) return `"${code}" is not an assigned ISO 3166-1 alpha-2 code.`;
  return countrySupportProblem(code);
}

function placeCodeProblem(code: string): string | null {
  const country = code.split('-', 1)[0] ?? code;
  const assigned = countryCodeProblem(country);
  if (assigned) return assigned;
  return code.includes('-') ? regionCodeProblem(code, country) : null;
}

function minutes(value: string): number | null {
  const match = /^(\d{2}):(\d{2})$/.exec(value);
  if (!match) return null;
  return Number(match[1]) * 60 + Number(match[2]);
}

function periodSpans(periods: Rec[], dayIndex: number | null): { ok: true; spans: Array<[number, number]> } | { ok: false; message: string } {
  const base = dayIndex === null ? 0 : dayIndex * 1440;
  const spans: Array<[number, number]> = [];
  for (const period of periods) {
    const opens = minutes(String(period.opens));
    const closesRaw = minutes(String(period.closes));
    if (opens === null || closesRaw === null) return { ok: false, message: 'a period is not a HH:MM time.' };
    let closes = closesRaw;
    if (closes === opens) return { ok: false, message: `period ${String(period.opens)}-${String(period.closes)} opens and closes at the same time.` };
    if (closes < opens) closes += 1440;
    spans.push([base + opens, base + closes]);
  }
  return { ok: true, spans };
}

/** SPEC.md §4.7.6.4. `wrap` copies spans that start on Monday forward one week so a Sunday overnight can meet them. */
function periodsOverlap(spans: Array<[number, number]>, wrap?: number): boolean {
  let ordered = [...spans].sort((a, b) => a[0] - b[0]);
  if (wrap !== undefined) {
    ordered = [...ordered, ...ordered.filter((span) => span[0] < 1440).map((span): [number, number] => [span[0] + wrap, span[1] + wrap])].sort((a, b) => a[0] - b[0]);
  }
  return ordered.some((span, index) => index + 1 < ordered.length && ordered[index + 1]![0] < span[1]);
}

function collectOpeningHourProblems(hours: Rec, where: string, out: Problem[]): void {
  const zones = knownTimeZones();
  if (zones.size > 0 && typeof hours.time_zone === 'string' && !zones.has(hours.time_zone)) {
    out.push({ path: `${where}/time_zone`, message: `"${hours.time_zone}" is not an IANA time zone.` });
  }
  const weekly = Array.isArray(hours.weekly) ? (hours.weekly as Rec[]) : [];
  const weeklySpans: Array<[number, number]> = [];
  const seenDays = new Set<string>();
  let overlapped = false;
  for (const entry of weekly) {
    const day = String(entry.day);
    if (seenDays.has(day)) {
      out.push({ path: `${where}/weekly`, message: `weekly lists ${day} more than once.` });
      continue;
    }
    seenDays.add(day);
    const periods = Array.isArray(entry.periods) ? (entry.periods as Rec[]) : [];
    const opens = periods.map((period) => String(period.opens));
    if (opens.some((value, index) => index > 0 && value < opens[index - 1]!)) {
      out.push({ path: `${where}/weekly`, message: `${day}: periods are not in order of opens.` });
    }
    const dayIndex = DAYS.indexOf(day);
    if (dayIndex < 0) continue;
    const spans = periodSpans(periods, dayIndex);
    if (!spans.ok) {
      out.push({ path: `${where}/weekly`, message: `${day}: ${spans.message}` });
      continue;
    }
    if (periodsOverlap(spans.spans)) {
      overlapped = true;
      out.push({ path: `${where}/weekly`, message: `${day}: periods overlap.` });
    }
    weeklySpans.push(...spans.spans);
  }
  if (!overlapped && periodsOverlap(weeklySpans, 7 * 1440)) {
    out.push({ path: `${where}/weekly`, message: "an overnight period overlaps the next day's hours." });
  }
  const exceptions = Array.isArray(hours.exceptions) ? (hours.exceptions as Rec[]) : [];
  const seenDates = new Set<string>();
  for (const entry of exceptions) {
    const date = String(entry.date);
    if (seenDates.has(date)) {
      out.push({ path: `${where}/exceptions`, message: `exceptions lists ${date} more than once.` });
      continue;
    }
    seenDates.add(date);
    const periods = Array.isArray(entry.periods) ? (entry.periods as Rec[]) : [];
    const opens = periods.map((period) => String(period.opens));
    if (opens.some((value, index) => index > 0 && value < opens[index - 1]!)) {
      out.push({ path: `${where}/exceptions`, message: `${date}: periods are not in order of opens.` });
    }
    const spans = periodSpans(periods, null);
    if (!spans.ok) out.push({ path: `${where}/exceptions`, message: `${date}: ${spans.message}` });
    else if (periodsOverlap(spans.spans)) out.push({ path: `${where}/exceptions`, message: `${date}: periods overlap.` });
  }
}

/** SPEC.md §4.7.6.4. Returned so a publisher can omit hours it cannot state honestly. */
export function openingHourProblems(hours: Rec, where = '/opening_hours'): Problem[] {
  const out: Problem[] = [];
  collectOpeningHourProblems(hours, where, out);
  return out;
}

function locationIdProblems(locations: Rec[], out: Problem[]): void {
  const seen = new Set<string>();
  locations.forEach((loc, index) => {
    if (typeof loc.location_id !== 'string') return;
    if (seen.has(loc.location_id)) {
      out.push({ path: `/locations/${index}/location_id`, message: `location_id "${loc.location_id}" is not unique.` });
    }
    seen.add(loc.location_id);
  });
}

function listingProblems(holder: Rec, where: string, out: Problem[]): void {
  if (!Array.isArray(holder.review_summaries)) return;
  const platforms = new Set<string>();
  (holder.review_summaries as Rec[]).forEach((item, index) => {
    const base = where === '' ? `/review_summaries/${index}` : `${where}/review_summaries/${index}`;
    if (typeof item.rating === 'number' && typeof item.rating_scale === 'number' && item.rating > item.rating_scale) {
      out.push({ path: `${base}/rating`, message: `rating ${item.rating} exceeds rating_scale ${item.rating_scale}.` });
    }
    if (typeof item.platform === 'string') {
      if (platforms.has(item.platform)) out.push({ path: `${base}/platform`, message: `more than one summary for ${item.platform}.` });
      platforms.add(item.platform);
    }
    httpsProblem(item.source_url, `${base}/source_url`, 'source_url', out);
  });
}

function areaProblems(areas: unknown, where: string, out: Problem[]): void {
  if (!Array.isArray(areas)) return;
  (areas as Rec[]).forEach((area, index) => {
    if (typeof area.code === 'string') {
      const problem = placeCodeProblem(area.code);
      if (problem) out.push({ path: `${where}/${index}/code`, message: problem });
    } else if (typeof area.country === 'string') {
      const problem = countryCodeProblem(area.country);
      if (problem) out.push({ path: `${where}/${index}/country`, message: problem });
    }
  });
}

const FORBIDDEN_KEYS = new Set(['recent_posts', 'contact_email', 'contact_phone']);

function forbiddenKeyProblems(value: unknown, path: string, out: Problem[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => forbiddenKeyProblems(item, `${path}/${index}`, out));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value as Rec)) {
    const here = path ? `${path}/${key}` : `/${key}`;
    if (FORBIDDEN_KEYS.has(key)) out.push({ path: here, message: `${key} is not allowed.` });
    forbiddenKeyProblems(child, here, out);
  }
}

function httpsProblem(value: unknown, path: string, label: string, out: Problem[]): void {
  if (typeof value === 'string' && !isSafeHttpsUrl(value)) out.push({ path, message: `${label} must be an https URL with a public DNS host name.` });
}

function socialProblems(profiles: unknown, where: string, out: Problem[]): void {
  if (!profiles || typeof profiles !== 'object' || Array.isArray(profiles)) return;
  for (const [network, url] of Object.entries(profiles as Rec)) httpsProblem(url, `${where}/${network}`, network, out);
}

function categoryProblems(categories: unknown, where: string, out: Problem[]): void {
  if (!categories || typeof categories !== 'object') return;
  const record = categories as Rec;
  const check = (category: unknown, path: string) => {
    if (!category || typeof category !== 'object') return;
    const taxonomy = (category as Rec).taxonomy;
    if (typeof taxonomy === 'string' && /^https?:\/\//i.test(taxonomy)) httpsProblem(taxonomy, path, 'taxonomy', out);
  };
  check(record.primary, `${where}/primary/taxonomy`);
  if (Array.isArray(record.additional)) record.additional.forEach((category, index) => check(category, `${where}/additional/${index}/taxonomy`));
}

function mediaProblems(items: unknown, out: Problem[]): void {
  if (!Array.isArray(items)) return;
  const ids = new Set<string>();
  const positions = new Set<number>();
  (items as Rec[]).forEach((item, index) => {
    if (typeof item.id === 'string') {
      if (ids.has(item.id)) out.push({ path: `/media/${index}/id`, message: `media id "${item.id}" is not unique.` });
      ids.add(item.id);
    }
    if (typeof item.position === 'number') {
      if (positions.has(item.position)) out.push({ path: `/media/${index}/position`, message: `media position ${item.position} is not unique.` });
      positions.add(item.position);
    }
    httpsProblem(item.url, `/media/${index}/url`, 'url', out);
    if (item.kind !== 'video' && item.decorative !== true && (typeof item.alt_text !== 'string' || item.alt_text.trim() === '')) {
      out.push({ path: `/media/${index}/alt_text`, message: 'an image needs alt_text unless decorative is true.' });
    }
  });
}

function listingUrlProblems(items: unknown, where: string, out: Problem[]): void {
  if (!Array.isArray(items)) return;
  (items as Rec[]).forEach((item, index) => httpsProblem(item.public_url, `${where}/${index}/public_url`, 'public_url', out));
}

function taxProblems(items: unknown, out: Problem[]): void {
  if (!Array.isArray(items)) return;
  const seen = new Set<string>();
  (items as Rec[]).forEach((item, index) => {
    if (typeof item.jurisdiction === 'string') {
      const problem = placeCodeProblem(item.jurisdiction);
      if (problem) out.push({ path: `/tax_registrations/${index}/jurisdiction`, message: problem });
    }
    const id = `${String(item.jurisdiction)}|${String(item.scheme)}|${String(item.number)}`;
    if (seen.has(id)) out.push({ path: `/tax_registrations/${index}`, message: 'tax registration jurisdiction, scheme and number are not unique.' });
    seen.add(id);
    if (typeof item.verification_expires_at === 'string' && typeof item.verified_at === 'string') {
      const expires = Date.parse(item.verification_expires_at);
      const verified = Date.parse(item.verified_at);
      if (!Number.isFinite(expires) || !Number.isFinite(verified) || expires <= verified) {
        out.push({ path: `/tax_registrations/${index}/verification_expires_at`, message: 'verification_expires_at must be later than verified_at.' });
      }
    }
  });
}

export function semanticProblems(record: Rec): { conformance: Problem[]; businessKey: Problem[] } {
  const conformance: Problem[] = [];
  const businessKey: Problem[] = [];
  const identity = record.identity_host as string;
  if (identityParts(identity) === null) {
    conformance.push({ path: '/identity_host', message: 'identity_host is not a valid DNS host name with an optional path.' });
  }
  (record.domains as string[]).forEach((domain, i) => {
    if (!isSafeHost(domain)) conformance.push({ path: `/domains/${i}`, message: `"${domain.slice(0, 80)}" is not a valid domain name.` });
  });
  const countryCode = nestedCountryCode(record.country);
  if (countryCode === null) {
    conformance.push({ path: '/country', message: 'country must be an object with code and name.' });
  } else {
    const countryProblem = countryCodeProblem(countryCode);
    if (countryProblem) conformance.push({ path: '/country/code', message: countryProblem });
  }
  const rootRegion = record.region as Rec | undefined;
  if (rootRegion && typeof rootRegion.code === 'string' && countryCode) {
    const problem = regionCodeProblem(rootRegion.code, countryCode);
    if (problem) conformance.push({ path: '/region/code', message: problem });
  }
  for (const key of ['website', 'logo_url', 'mcp_server_url', 'blog_url', 'rss_url'] as const) {
    const value = record[key];
    if (typeof value === 'string' && !isSafeHttpsUrl(value)) conformance.push({ path: `/${key}`, message: `${key} must be an https URL with a public DNS host name.` });
  }
  for (const collection of ['services', 'links'] as const) {
    const items = record[collection];
    if (!Array.isArray(items)) continue;
    items.forEach((item: Rec, i) => {
      if (typeof item.url === 'string' && !isSafeHttpsUrl(item.url)) conformance.push({ path: `/${collection}/${i}/url`, message: 'url must be an https URL with a public DNS host name.' });
    });
  }
  forbiddenKeyProblems(record, '', conformance);
  socialProblems(record.social_profiles, '/social_profiles', conformance);
  categoryProblems(record.categories, '/categories', conformance);
  mediaProblems(record.media, conformance);
  const locations = record.locations;
  if (Array.isArray(locations)) {
    locations.forEach((loc: Rec, i) => {
      for (const key of ['street', 'city', 'postal_code'] as const) {
        if (key in loc) conformance.push({ path: `/locations/${i}/${key}`, message: `${key} is not a location member; use address.` });
      }
      const addr = loc.address as Rec | undefined;
      if (addr && typeof addr.country === 'object' && addr.country !== null) {
        const code = (addr.country as Rec).code as string;
        if (typeof code === 'string') {
          const problem = countryCodeProblem(code);
          if (problem) conformance.push({ path: `/locations/${i}/address/country/code`, message: problem });
        }
      }
      const region = addr?.region as Rec | undefined;
      const regionCode = region?.code;
      const addressCountry = (addr?.country as Rec | undefined)?.code;
      if (typeof regionCode === 'string' && typeof addressCountry === 'string') {
        const problem = regionCodeProblem(regionCode, addressCountry);
        if (problem) conformance.push({ path: `/locations/${i}/address/region/code`, message: problem });
      }
      const geo = loc.geo as Rec | undefined;
      if (geo) {
        const street = addr && Array.isArray(addr.street_lines) && addr.street_lines.length > 0;
        if (!street) conformance.push({ path: `/locations/${i}/geo`, message: 'geo requires address.street_lines.' });
        const lat = geo.latitude as number;
        const lon = geo.longitude as number;
        if (typeof lat !== 'number' || lat < -90 || lat > 90 || typeof lon !== 'number' || lon < -180 || lon > 180) {
          conformance.push({ path: `/locations/${i}/geo`, message: 'geo coordinates out of valid WGS 84 range.' });
        }
      }
      httpsProblem(loc.website, `/locations/${i}/website`, 'website', conformance);
      socialProblems(loc.social_profiles, `/locations/${i}/social_profiles`, conformance);
      categoryProblems(loc.categories, `/locations/${i}/categories`, conformance);
      listingUrlProblems(loc.external_listings, `/locations/${i}/external_listings`, conformance);
      const hours = loc.opening_hours;
      if (hours && typeof hours === 'object') collectOpeningHourProblems(hours as Rec, `/locations/${i}/opening_hours`, conformance);
      listingProblems(loc, `/locations/${i}`, conformance);
      areaProblems(loc.service_areas, `/locations/${i}/service_areas`, conformance);
    });
    locationIdProblems(locations as Rec[], conformance);
  }
  listingProblems(record, '', conformance);
  taxProblems(record.tax_registrations, conformance);
  const key = record.business_key;
  if (typeof key === 'string') {
    const parsed = parseBusinessKey(key);
    if (!parsed.ok) businessKey.push({ path: '/business_key', message: parsed.message });
    else {
      if (countryCode && parsed.country !== countryCode.toLowerCase()) businessKey.push({ path: '/business_key', message: "business_key's country does not match country." });
      if (parsed.number !== String(record.registration_number).toUpperCase()) {
        businessKey.push({ path: '/business_key', message: "business_key's registration number does not match registration_number." });
      }
    }
  }
  return { conformance, businessKey };
}

export interface LinkCheck {
  identityHostMatches: boolean;
  queriedDomainInRecord: boolean;
  businessKey: Problem[];
}

export function linkChecks(record: Rec, domain: string, assertion: AbizAssertion): LinkCheck {
  const identity = identityParts(record.identity_host as string);
  const identityHostMatches = identity !== null && identity === assertion.h;
  const declared = new Set((record.domains as string[]).map((d) => d.toLowerCase().replace(/\.$/, '')));
  const queriedDomainInRecord = declared.has(domain);
  const businessKey: Problem[] = [];
  const key = record.business_key;
  if (assertion.k !== undefined && typeof key === 'string' && !sameBusinessKey(assertion.k, key)) {
    businessKey.push({ path: '/business_key', message: 'The DNS k= tag and the record business_key differ.' });
  } else if (key === undefined && assertion.k !== undefined) {
    businessKey.push({ path: '/business_key', message: 'The DNS assertion has k= but the record has no business_key.' });
  }
  return { identityHostMatches, queriedDomainInRecord, businessKey };
}
