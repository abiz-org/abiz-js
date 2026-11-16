// SPDX-License-Identifier: Apache-2.0
// Which resolved addresses a fetch may connect to (SPEC.md §9; test-vectors/addresses.json).
// Adapted from the ABIZ reference resolver (resolve.abizrecord.org).
// An IPv4 address must be outside every special-purpose block in the IANA registry (RFC 6890 and
// successors); an IPv6 address must be global unicast (2000::/3) outside the documentation, 6to4
// and Teredo ranges, whose embedded IPv4 could be private. IPv4-mapped, NAT64 and every other
// IPv6 range outside 2000::/3 are refused.

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ip4(a: number, b: number, c: number, d: number): number {
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

/** [network, prefix length] of IPv4 blocks that are never a public web origin. */
const V4_SPECIAL: Array<[number, number]> = [
  [ip4(0, 0, 0, 0), 8],
  [ip4(10, 0, 0, 0), 8],
  [ip4(100, 64, 0, 0), 10],
  [ip4(127, 0, 0, 0), 8],
  [ip4(169, 254, 0, 0), 16],
  [ip4(172, 16, 0, 0), 12],
  [ip4(192, 0, 0, 0), 24],
  [ip4(192, 0, 2, 0), 24],
  [ip4(192, 31, 196, 0), 24],
  [ip4(192, 52, 193, 0), 24],
  [ip4(192, 88, 99, 0), 24],
  [ip4(192, 168, 0, 0), 16],
  [ip4(192, 175, 48, 0), 24],
  [ip4(198, 18, 0, 0), 15],
  [ip4(198, 51, 100, 0), 24],
  [ip4(203, 0, 113, 0), 24],
  [ip4(224, 0, 0, 0), 4],
  [ip4(240, 0, 0, 0), 4],
];

function parseV4(text: string): number | null {
  const m = V4.exec(text);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return ip4(o[0]!, o[1]!, o[2]!, o[3]!);
}

function v4Public(n: number): boolean {
  return !V4_SPECIAL.some(([net, len]) => (n & ((0xffffffff << (32 - len)) >>> 0)) >>> 0 === net);
}

/** The eight 16-bit groups of an IPv6 address (a dotted IPv4 tail allowed), or null. */
function ipv6Groups(text: string): number[] | null {
  let t = text.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const tail = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(t);
  if (tail) {
    const n = parseV4(tail[2]!);
    if (n === null) return null;
    t = `${tail[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const part = (s: string) => (s === '' ? [] : s.split(':'));
  const head = part(halves[0]!);
  const rest = halves.length === 2 ? part(halves[1]!) : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? fill : 0).fill('0'), ...rest];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

/** True only for an address a consumer may connect to: public unicast IPv4 or global unicast IPv6. */
export function isPublicAddress(address: string): boolean {
  const v4 = parseV4(address.trim());
  if (v4 !== null) return v4Public(v4);
  const g = ipv6Groups(address.trim());
  if (!g) return false;
  const first = g[0]!;
  if ((first & 0xe000) !== 0x2000) return false; // outside 2000::/3: ::, ::1, ::ffff:0:0/96, 64:ff9b::/96, fc00::/7, fe80::/10, ff00::/8
  if (first === 0x2001 && g[1] === 0x0db8) return false; // 2001:db8::/32 documentation
  if (first === 0x2001 && g[1]! < 0x0200) return false; // 2001::/23 IETF protocol assignments (Teredo, ORCHID, benchmarking)
  if (first === 0x2002) return false; // 6to4: the embedded IPv4 is not checked
  if (first === 0x3fff && g[1]! < 0x1000) return false; // 3fff::/20 documentation
  return true;
}
