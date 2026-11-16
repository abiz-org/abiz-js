// SPDX-License-Identifier: Apache-2.0
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org), relicensed under Apache-2.0.
// I-JSON (RFC 7493 §2.3) forbids repeated member names, and SPEC §4.6 requires a
// verifier to reject them: JSON.parse keeps the last one silently, so the signed bytes and what a
// reader sees could differ. Run on text that JSON.parse has already accepted.

/** JSON Pointer of the first object with a repeated member name (after unescaping), or null. */
export function firstDuplicateMember(text: string): string | null {
  const stack: Array<{ keys: Set<string> | null; path: string; index: number; key: string | null }> = [];
  let expectKey = false;
  let i = 0;
  const escape = (s: string) => s.replace(/~/g, '~0').replace(/\//g, '~1');
  const childPath = () => {
    const top = stack[stack.length - 1];
    if (!top) return '';
    return top.keys ? `${top.path}/${escape(top.key ?? '')}` : `${top.path}/${top.index}`;
  };
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (expectKey && top?.keys) {
        const name = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(name)) return `${top.path}/${escape(name)}`;
        top.keys.add(name);
        top.key = name;
        expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === '{' || c === '[') {
      stack.push({ keys: c === '{' ? new Set() : null, path: childPath(), index: 0, key: null });
      expectKey = c === '{';
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top?.keys) expectKey = true;
      else if (top) top.index += 1;
    }
    i += 1;
  }
  return null;
}
