// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// The ABIZ 1.1 business key (SPEC.md §4.2, proposed): `country "-" [subdivision "-"] reg-number`,
// used as DNS `k` and record `business_key`. Everything about `k` lives here so a later revision
// of the rule is a change to one file.
//
// - country: an assigned ISO 3166-1 alpha-2 code (schema/iso3166.json, copied from the spec repo);
// - subdivision: required for us (50 states and dc) and ae (7 emirates), required for a
//   provincial ca key and absent for a federal one, forbidden for every other country; when
//   present, an ISO 3166-2 code of that country from the same file;
// - reg-number: ASCII letters and digits only, never normalised by a consumer;
// - at most 128 characters; compared case-insensitively. Canonical form: lowercase country and
//   subdivision, uppercase number (`us-or-123456`, `gb-SC123456`).
import iso3166 from '../schema/iso3166.json';

const COUNTRIES: ReadonlySet<string> = new Set((iso3166 as { countries: string[] }).countries);
const SUBDIVISIONS: Readonly<Record<string, ReadonlySet<string>>> = Object.fromEntries(
  Object.entries((iso3166 as { subdivisions: Record<string, string[]> }).subdivisions).map(([c, codes]) => [c, new Set(codes)]),
);
/** SPEC.md §4.2.2. `provincial`: required, except for a federal (Corporations Canada) key. */
const SUBDIVISION_RULE: Readonly<Record<string, 'required' | 'provincial'>> = { us: 'required', ae: 'required', ca: 'provincial' };
const REG_NUMBER = /^[A-Za-z0-9]+$/;
export const BUSINESS_KEY_MAX = 128;
/** SPEC.md §4.2.7. Assigned, but ABIZ does not support a business there. */
export const UNSUPPORTED_COUNTRIES: ReadonlySet<string> = new Set(['kp']);

export type BusinessKey = { ok: true; country: string; subdivision: string | null; number: string; canonical: string } | { ok: false; message: string };

/** True when `code` is an assigned ISO 3166-1 alpha-2 code, in any case. `kp` is assigned; {@link countrySupportProblem} rejects it. */
export function isAssignedCountry(code: string): boolean {
  return /^[A-Za-z]{2}$/.test(code) && COUNTRIES.has(code.toLowerCase());
}

/** SPEC.md §4.2.7: `kp` is assigned and still not a valid ABIZ country. */
export function countrySupportProblem(code: string): string | null {
  if (!UNSUPPORTED_COUNTRIES.has(code.toLowerCase())) return null;
  return `"${code}" is not supported by ABIZ (SPEC section 4.2.7).`;
}

/**
 * An ISO 3166-2 region code against its country (SPEC.md §4.7.13).
 * Subdivisions are confirmed only for us, ca and ae; every other country is checked for form and country part.
 */
export function regionCodeProblem(code: string, country: string): string | null {
  const dash = code.indexOf('-');
  const prefix = dash === -1 ? code : code.slice(0, dash);
  const sub = dash === -1 ? '' : code.slice(dash + 1);
  if (prefix.toLowerCase() !== country.toLowerCase()) return `region code "${code}" does not belong to country "${country}".`;
  const known = SUBDIVISIONS[country.toLowerCase()];
  if (known && !known.has(sub.toLowerCase())) return `region code "${code}" is not an assigned ISO 3166-2 code.`;
  return null;
}

/** Parse a business key under SPEC.md §4.2.1–4.2.2, returning its canonical parts. */
export function parseBusinessKey(value: string): BusinessKey {
  if (value.length > BUSINESS_KEY_MAX) return { ok: false, message: `A business key is at most ${BUSINESS_KEY_MAX} characters.` };
  const parts = value.split('-');
  if (parts.length !== 2 && parts.length !== 3) {
    return { ok: false, message: 'A business key is country-number or country-subdivision-number, for example gb-01234567 or us-or-123456.' };
  }
  const [rawCountry, rawSub, rawNumber] = parts.length === 2 ? [parts[0]!, null, parts[1]!] : [parts[0]!, parts[1]!, parts[2]!];
  if (!isAssignedCountry(rawCountry)) return { ok: false, message: `"${rawCountry.slice(0, 8)}" is not an assigned ISO 3166-1 alpha-2 country code (the United Kingdom is gb).` };
  const unsupported = countrySupportProblem(rawCountry);
  if (unsupported) return { ok: false, message: unsupported };
  const country = rawCountry.toLowerCase();
  if (!REG_NUMBER.test(rawNumber)) return { ok: false, message: 'The registration number in a business key must be ASCII letters and digits only.' };
  const rule = SUBDIVISION_RULE[country];
  let subdivision: string | null = null;
  if (rawSub === null) {
    if (rule === 'required') return { ok: false, message: `A business key for ${country} must include the subdivision, for example ${country === 'us' ? 'us-or-123456' : 'ae-du-1234567'}.` };
  } else {
    if (!/^[A-Za-z0-9]{1,3}$/.test(rawSub)) return { ok: false, message: 'A business key subdivision is 1 to 3 ASCII letters or digits.' };
    if (!rule) return { ok: false, message: `A business key for ${country} must not include a subdivision.` };
    subdivision = rawSub.toLowerCase();
    if (!SUBDIVISIONS[country]?.has(subdivision)) return { ok: false, message: `${country}-${subdivision} is not a permitted ISO 3166-2 subdivision for a business key.` };
  }
  const number = rawNumber.toUpperCase();
  return { ok: true, country, subdivision, number, canonical: [country, subdivision, number].filter(Boolean).join('-') };
}

/** Two business keys are the same key when they match ignoring ASCII case (SPEC.md §4.2.4). */
export function sameBusinessKey(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
