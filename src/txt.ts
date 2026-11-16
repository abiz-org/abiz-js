// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// The `_abiz` TXT assertion (SPEC.md §3, ABIZ 1.1): reconstructing TXT RDATA, selecting the one
// `v=abiz1` record, parsing its tag list (DKIM/DMARC-style whitespace) and checking the `p` key.
import { parseBusinessKey } from './businessKey.js';
import { identityHostname, identityParts, isNonPublicHost } from './host.js';

/**
 * One TXT record's value from a DNS-over-HTTPS JSON answer. A record of several
 * character-strings arrives quoted (`"part one" "part two"`); the strings are joined with
 * nothing between them (RFC 7208 §3.3 style). `\"`, `\\` and `\DDD` escapes are decoded.
 * A value that is not quoted (some resolvers join the strings themselves) is returned as is.
 */
export function decodeTxtData(data: string): string {
  const text = data.trim();
  if (!text.startsWith('"')) return text;
  let out = '';
  let i = 0;
  while (i < text.length) {
    while (i < text.length && text[i] === ' ') i++;
    if (i >= text.length) break;
    if (text[i] !== '"') {
      // Not a sequence of quoted strings after all: keep the raw remainder.
      out += text.slice(i);
      break;
    }
    i++;
    while (i < text.length && text[i] !== '"') {
      const ch = text[i]!;
      if (ch === '\\' && i + 1 < text.length) {
        const next = text.slice(i + 1, i + 4);
        if (/^[0-9]{3}$/.test(next)) {
          out += String.fromCharCode(Number(next));
          i += 4;
          continue;
        }
        out += text[i + 1];
        i += 2;
        continue;
      }
      out += ch;
      i++;
    }
    i++; // closing quote
  }
  return out;
}

/**
 * True when the value's first tag is `v=abiz1` (SPEC.md §3.1.1, ABIZ 1.1): optional SP/HTAB
 * before the tag and around `=`, case-sensitive, then the end of the value or `;` (after optional
 * SP/HTAB). `V=ABIZ1`, `v=abiz1x` and `h=…;v=abiz1` are not ABIZ assertions and are not counted.
 */
export function isAbizAssertion(value: string): boolean {
  return /^[ \t]*v[ \t]*=[ \t]*abiz1[ \t]*(;|$)/.test(value);
}

/** Looks like an attempt at an ABIZ assertion, but the first tag is not `v=abiz1`. */
export function isNearMissAssertion(value: string): boolean {
  return !isAbizAssertion(value) && /^\s*"?\s*v\s*=\s*abiz/i.test(value);
}

export interface AbizAssertion {
  /** The canonical record host (host lower case, path as published). */
  h: string;
  k?: string;
  /** An Ed25519 public key, standard base64 (SPEC.md §3.3.2). Required (SPEC.md §3.3.1); any other value is invalid. */
  p: string;
  /** Tags the specification does not define, kept for reference and otherwise ignored. */
  unknown: Record<string, string>;
}

export type AssertionProblem = 'bad_pointer' | 'duplicate_tag' | 'missing_h' | 'unsafe_host' | 'invalid_key';

export type ParsedAssertion = { ok: true; assertion: AbizAssertion } | { ok: false; code: AssertionProblem; message: string };

const RECOGNISED = new Set(['v', 'h', 'k', 'p']);
/** SP and HTAB are the only whitespace allowed between tokens (WSP). */
const WSP = /^[ \t]+|[ \t]+$/g;
/** Characters never allowed anywhere: controls (other than HTAB), DEL, and any non-WSP Unicode space. */
const FORBIDDEN = /[\u0000-\u0008\u000a-\u001f\u007f]|(?![ \t])\s/;
/** `tag-name`: no whitespace, `;` or `=`. */
const TAG_NAME = /^[^\s;=\u0000-\u001f\u007f]+$/;
/** `tag-value`: no whitespace or `;` (`=` is allowed). */
const TAG_VALUE = /^[^\s;\u0000-\u001f\u007f]+$/;
const STD_BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;

const trimWsp = (s: string) => s.replace(WSP, '');

/**
 * True when `value` is an ABIZ 1.1 `p` key (SPEC.md §3.3.2): exactly 44 characters of standard
 * base64 (RFC 4648 §4) ending in one `=`, decoding to 32 bytes, and canonical (encoding the bytes
 * again gives the same text). Base64url, unpadded or `==`-padded values and 1.0 hex tokens fail.
 */
export function isAbizPublicKey(value: string): boolean {
  if (!STD_BASE64_KEY.test(value)) return false;
  let bytes: string;
  try {
    bytes = atob(value);
  } catch {
    return false;
  }
  return bytes.length === 32 && btoa(bytes) === value;
}

export type TagList = { ok: true; tags: [name: string, value: string][] } | { ok: false; message: string };

/**
 * Split an assertion into its tags under the ABIZ 1.1 tag-list syntax (SPEC.md §3.1.1, as DKIM
 * RFC 6376 §3.2 and DMARC RFC 7489 §6.4): optional SP/HTAB around `;` and `=`, leading and
 * trailing SP/HTAB, at most one trailing `;`. Every tag is `name=value` with both non-empty and
 * no whitespace inside; a value may contain `=` (split on the first). `v=abiz1` must be first.
 */
export function parseTagList(value: string): TagList {
  if (FORBIDDEN.test(value)) {
    return { ok: false, message: 'The ABIZ TXT value contains a line break, control character or non-ASCII space. Only spaces and tabs are allowed, and only around ";" and "=".' };
  }
  let body = trimWsp(value);
  if (body.endsWith(';')) body = trimWsp(body.slice(0, -1));
  const tags: [string, string][] = [];
  for (const raw of body.split(';')) {
    const part = trimWsp(raw);
    const eq = part.indexOf('=');
    if (eq <= 0) {
      return { ok: false, message: `Every tag must be name=value (found "${clip(part)}"). An empty tag (";;") or more than one trailing ";" is invalid.` };
    }
    const name = trimWsp(part.slice(0, eq));
    const val = trimWsp(part.slice(eq + 1));
    if (!TAG_NAME.test(name) || !val) {
      return { ok: false, message: `Every tag must be name=value with both parts present (found "${clip(part)}").` };
    }
    if (!TAG_VALUE.test(val)) {
      return { ok: false, message: `A tag value must not contain whitespace (found "${clip(part)}"). Spaces are allowed only around ";" and "=".` };
    }
    tags.push([name, val]);
  }
  const first = tags[0];
  if (!first || first[0] !== 'v' || first[1] !== 'abiz1') return { ok: false, message: 'The first tag must be v=abiz1.' };
  return { ok: true, tags };
}

/**
 * Parse one `v=abiz1` value under ABIZ 1.1 (SPEC.md §3.1.1–§3.3.7): the tag-list syntax
 * above, recognised tags (`v`, `h`, `k`, `p`, case-sensitive) at most once, `h` required and a safe
 * host with an optional path, `k` a business key, and `p` required and an Ed25519 public key in
 * standard base64. Unknown tags are ignored, repeats included. A value without `p`, or whose `p` is
 * not a key (an opaque 1.0 token), is `invalid_key`.
 */
export function parseAssertion(value: string): ParsedAssertion {
  const list = parseTagList(value);
  if (!list.ok) return { ok: false, code: 'bad_pointer', message: list.message };
  const seen = new Map<string, string>();
  const unknown: Record<string, string> = {};
  for (const [name, val] of list.tags) {
    if (RECOGNISED.has(name)) {
      if (seen.has(name)) return { ok: false, code: 'duplicate_tag', message: `The tag ${name}= appears more than once.` };
      seen.set(name, val);
    } else if (!(name in unknown)) {
      unknown[name] = val;
    }
  }
  const rawH = seen.get('h');
  if (!rawH) return { ok: false, code: 'missing_h', message: 'The ABIZ TXT value has no h= tag naming the record host.' };
  const h = identityParts(rawH);
  if (!h) {
    return { ok: false, code: 'bad_pointer', message: 'h= must be a host name with an optional path: no scheme, port, user name, query, fragment or "." segments.' };
  }
  if (isNonPublicHost(identityHostname(h))) return { ok: false, code: 'unsafe_host', message: 'h= names a special-use or private-network host.' };
  const k = seen.get('k');
  if (k !== undefined) {
    const key = parseBusinessKey(k);
    if (!key.ok) return { ok: false, code: 'bad_pointer', message: `k= is not an ABIZ 1.1 business key: ${key.message}` };
  }
  const p = seen.get('p');
  if (p === undefined) {
    return {
      ok: false,
      code: 'invalid_key',
      message:
        'The ABIZ TXT value has no p= tag. p is required (SPEC.md §3.3.1): publish p= with the business\'s Ed25519 public key, ' +
        '44 characters of standard base64 ending in one "=".',
    };
  }
  if (!isAbizPublicKey(p)) {
    return {
      ok: false,
      code: 'invalid_key',
      message:
        'p= must be an Ed25519 public key: 44 characters of standard base64 (A-Z a-z 0-9 + /) ending in one "=", decoding to 32 bytes (SPEC.md §3.3.2). ' +
        'Hex strings and base64url values are not accepted: publish p= as the key in standard base64.',
    };
  }
  const assertion: AbizAssertion = { h, p, unknown };
  if (k !== undefined) assertion.k = k;
  return { ok: true, assertion };
}

function clip(value: string): string {
  return value.length > 40 ? `${value.slice(0, 40)}…` : value;
}
