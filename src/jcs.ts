// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// RFC 8785 JSON Canonicalization Scheme (JCS), for the record signature (signature.ts).
/** Thrown for a value RFC 8785 cannot canonicalise (I-JSON only). */
export class JcsError extends Error {}

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function str(value: string): string {
  if (LONE_SURROGATE.test(value)) throw new JcsError('a string holds a lone surrogate (not I-JSON)');
  // JSON.stringify escapes exactly as RFC 8785 §3.2.2.2 asks: \b \t \n \f \r \" \\, other
  // controls as \u00xx in lowercase hex, everything else as itself.
  return JSON.stringify(value);
}

function num(value: number): string {
  if (!Number.isFinite(value)) throw new JcsError('a number is NaN or infinite (not I-JSON)');
  // ECMAScript Number serialisation, which RFC 8785 §3.2.2.3 adopts; -0 is written 0.
  return Object.is(value, -0) ? '0' : JSON.stringify(value);
}

/**
 * RFC 8785 JSON Canonicalization Scheme: no whitespace, object members sorted by the UTF-16 code
 * units of their names, ECMAScript number and string serialisation. `undefined` members are
 * dropped, as JSON.stringify drops them; any other non-JSON value throws {@link JcsError}.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return num(value);
    case 'string':
      return str(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',')}]`;
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) throw new JcsError('only plain objects can be canonicalised');
      const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
      // Default string order is by UTF-16 code units, which is what RFC 8785 §3.2.3 asks for.
      entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, v]) => `${str(k)}:${canonicalJson(v)}`).join(',')}}`;
    }
    default:
      throw new JcsError(`a ${typeof value} is not a JSON value`);
  }
}
