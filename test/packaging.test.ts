// The bundled schema and country list are the pinned files, unchanged.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ABIZ_SCHEMA, ABIZ_WELL_KNOWN_SCHEMA, BUNDLED_FILES, LIBRARY_VERSION, USER_AGENT } from '../src/index.js';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const sha256 = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');

// The values published in test-vectors/README.md.
const README_SHA256: Record<string, string> = {
  'abiz-business-record-v1.1.schema.json': '3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24',
  'abiz-well-known-v1.1.schema.json': '5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741',
  'iso3166.json': '0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527',
};

describe('bundled files', () => {
  it.each(Object.entries(README_SHA256))('%s has the published SHA-256', (file, digest) => {
    expect(sha256(here(`../schema/${file}`))).toBe(digest);
    expect(BUNDLED_FILES[file as keyof typeof BUNDLED_FILES]).toBe(digest);
  });

  it('the README in test-vectors lists the same digests', () => {
    const readme = readFileSync(here('../test-vectors/README.md'), 'utf8');
    for (const digest of Object.values(README_SHA256)) expect(readme).toContain(digest);
  });

  it('the schemas the code uses are the bundled files', () => {
    expect(ABIZ_SCHEMA).toEqual(JSON.parse(readFileSync(here('../schema/abiz-business-record-v1.1.schema.json'), 'utf8')));
    expect(ABIZ_WELL_KNOWN_SCHEMA).toEqual(JSON.parse(readFileSync(here('../schema/abiz-well-known-v1.1.schema.json'), 'utf8')));
  });

  it('the version and User-Agent match package.json', () => {
    const pkg = JSON.parse(readFileSync(here('../package.json'), 'utf8')) as { version: string };
    expect(LIBRARY_VERSION).toBe(pkg.version);
    expect(USER_AGENT).toBe(`abiz-js/${pkg.version} (+https://abizrecord.org)`);
  });
});
