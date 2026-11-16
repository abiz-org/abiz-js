#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// abiz check <domain|website> [--json]
// Exit status: 0 resolved, 1 any other result, 2 usage error.
import { resolve } from './node.js';
import { LIBRARY_VERSION } from './transport.js';

const USAGE = `Usage: abiz check <domain or website> [--json]

Finds the domain's _abiz DNS record, fetches the ABIZ business record it points to and checks it
(ABIZ 1.1). Exit status 0 when the record resolved, 1 otherwise, 2 for a usage error.`;

async function main(argv: string[]): Promise<number> {
  const args = argv.filter((a) => a !== '--json');
  const json = argv.includes('--json');
  if (args[0] === '--version' || args[0] === '-v') {
    process.stdout.write(`${LIBRARY_VERSION}\n`);
    return 0;
  }
  if (args[0] === '--help' || args[0] === '-h') {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (args[0] !== 'check' || args.length !== 2 || args[1]!.startsWith('-')) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const target = args[1]!;
  const input = /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? { website: target } : { domain: target };
  const result = await resolve(input);
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    const lines = [`${result.domain ?? target}: ${result.status}${result.code ? ` (${result.code})` : ''}`, result.message];
    if (result.discovery) {
      lines.push(`  found by: ${result.discovery.method}${result.discovery.dns_value ? `  ${result.discovery.dns_value}` : ''}`);
      if (result.discovery.record_url) lines.push(`  record:   ${result.discovery.record_url}`);
    }
    const name = result.record?.business_name;
    if (typeof name === 'string') lines.push(`  business: ${name} (the publisher's own claim)`);
    for (const d of result.details) lines.push(`  ${d.path}: ${d.message}`);
    if (result.truncated) lines.push('  (more problems not shown)');
    for (const w of result.warnings) lines.push(`  warning ${w.code}: ${w.message}`);
    process.stdout.write(`${lines.join('\n')}\n`);
  }
  return result.status === 'resolved' ? 0 : 1;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`abiz: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  },
);
