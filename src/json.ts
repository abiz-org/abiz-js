// SPDX-License-Identifier: Apache-2.0
// Reading a record as I-JSON (SPEC.md §4.6) within limits: nesting no deeper than 16 and at most
// 5,000 object members, measured before JSON.parse so a hostile record cannot exhaust the parser
// or the validator. Repeated member names are found by duplicates.ts.

export const MAX_RECORD_BYTES = 65_536;
export const MAX_RECORD_DEPTH = 16;
export const MAX_RECORD_KEYS = 5_000;

export type JsonParse = { ok: true; value: unknown } | { ok: false; problem: 'invalid_json' | 'too_deep' | 'too_many_keys' };

/** Nesting depth and object member count in one linear pass, stopping once a limit is passed. */
function scanJson(text: string, maxDepth: number, maxKeys: number): { depth: number; keys: number } {
  let depth = 0;
  let deepest = 0;
  let keys = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (ch === 0x5c) i++;
      else if (ch === 0x22) inString = false;
      continue;
    }
    if (ch === 0x22) inString = true;
    else if (ch === 0x7b || ch === 0x5b) {
      depth++;
      if (depth > deepest) deepest = depth;
      if (deepest > maxDepth) break;
    } else if (ch === 0x7d || ch === 0x5d) depth--;
    else if (ch === 0x3a) {
      // In valid JSON every ':' outside a string separates a member name from its value.
      keys++;
      if (keys > maxKeys) break;
    }
  }
  return { depth: deepest, keys };
}

/** JSON.parse after the depth and member-count limits. */
export function parseRecordJson(text: string): JsonParse {
  const scan = scanJson(text, MAX_RECORD_DEPTH, MAX_RECORD_KEYS);
  if (scan.depth > MAX_RECORD_DEPTH) return { ok: false, problem: 'too_deep' };
  if (scan.keys > MAX_RECORD_KEYS) return { ok: false, problem: 'too_many_keys' };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, problem: 'invalid_json' };
  }
}
