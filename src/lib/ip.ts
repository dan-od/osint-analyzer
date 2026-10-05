// IPv4/IPv6 parsing and classification. Pure functions, used in the browser
// (input detection, bulk pre-filtering) and on the server (DNSBL, CIDR feeds).

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  /** Canonical text form (IPv4 dotted quad, IPv6 RFC 5952 compressed lowercase) */
  address: string;
  value: bigint;
}

const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function parseIpv4(input: string): bigint | null {
  const parts = input.split('.');
  if (parts.length !== 4 || !parts.every((p) => IPV4_OCTET.test(p))) return null;
  return parts.reduce((acc, p) => acc * BigInt(256) + BigInt(Number(p)), BigInt(0));
}

function parseIpv6(input: string): bigint | null {
  let text = input;
  // Embedded IPv4 tail, e.g. ::ffff:192.0.2.1
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.', lastColon)) {
    const v4 = parseIpv4(text.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = (v4 >> BigInt(16)).toString(16);
    const lo = (v4 & BigInt(0xffff)).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;

  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.reduce((acc, g) => (acc << BigInt(16)) + BigInt(parseInt(g, 16)), BigInt(0));
}

function formatIpv4(value: bigint): string {
  return [24, 16, 8, 0].map((shift) => Number((value >> BigInt(shift)) & BigInt(255))).join('.');
}

function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & BigInt(0xffff)));
  // Longest run (≥2) of zero groups becomes "::"
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

const IPV4_MAPPED_PREFIX = BigInt(0xffff) << BigInt(32);
const IPV4_MAPPED_MASK = ~((BigInt(1) << BigInt(32)) - BigInt(1)) & ((BigInt(1) << BigInt(128)) - BigInt(1));

/** Accepts plain, bracketed ("[2001:db8::1]") and zone-suffixed ("fe80::1%eth0") forms. */
export function parseIp(raw: string): ParsedIp | null {
  let input = raw.trim();
  if (input.startsWith('[') && input.endsWith(']')) input = input.slice(1, -1);
  input = input.replace(/%[\w.-]+$/, '');

  const v4 = parseIpv4(input);
  if (v4 !== null) return { version: 4, address: formatIpv4(v4), value: v4 };

  if (!input.includes(':')) return null;
  const v6 = parseIpv6(input);
  if (v6 === null) return null;
  // ::ffff:a.b.c.d is just an IPv4 address
  if ((v6 & IPV4_MAPPED_MASK) === IPV4_MAPPED_PREFIX) {
    const inner = v6 & BigInt(0xffffffff);
    return { version: 4, address: formatIpv4(inner), value: inner };
  }
  return { version: 6, address: formatIpv6(v6), value: v6 };
}

export interface CidrRange {
  version: IpVersion;
  start: bigint;
  end: bigint;
}

export function parseCidr(text: string): CidrRange | null {
  const [addr, prefixText] = text.trim().split('/');
  const ip = parseIp(addr);
  if (!ip) return null;
  const bits = ip.version === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const hostBits = BigInt(bits - prefix);
  const start = (ip.value >> hostBits) << hostBits;
  return { version: ip.version, start, end: start + (BigInt(1) << hostBits) - BigInt(1) };
}

function inRange(ip: ParsedIp, range: CidrRange): boolean {
  return ip.version === range.version && ip.value >= range.start && ip.value <= range.end;
}

// Private, loopback, link-local, CGNAT, documentation, multicast and other
// special-purpose ranges (IANA IPv4/IPv6 special-purpose registries)
const INTERNAL_RANGES: { range: CidrRange; label: string }[] = (
  [
    ['0.0.0.0/8', 'This network'],
    ['10.0.0.0/8', 'Private network (RFC 1918)'],
    ['100.64.0.0/10', 'Carrier-grade NAT (RFC 6598)'],
    ['127.0.0.0/8', 'Loopback'],
    ['169.254.0.0/16', 'Link-local'],
    ['172.16.0.0/12', 'Private network (RFC 1918)'],
    ['192.0.0.0/24', 'IETF protocol assignments'],
    ['192.0.2.0/24', 'Documentation (TEST-NET-1)'],
    ['192.88.99.0/24', 'Deprecated 6to4 relay anycast'],
    ['192.168.0.0/16', 'Private network (RFC 1918)'],
    ['198.18.0.0/15', 'Benchmarking'],
    ['198.51.100.0/24', 'Documentation (TEST-NET-2)'],
    ['203.0.113.0/24', 'Documentation (TEST-NET-3)'],
    ['224.0.0.0/4', 'Multicast'],
    ['240.0.0.0/4', 'Reserved'],
    ['::/128', 'Unspecified address'],
    ['::1/128', 'Loopback'],
    ['64:ff9b:1::/48', 'Local-use NAT64'],
    ['100::/64', 'Discard-only'],
    ['2001::/23', 'IETF protocol assignments'],
    ['2001:db8::/32', 'Documentation'],
    ['3fff::/20', 'Documentation'],
    ['5f00::/16', 'Segment routing (SRv6) SIDs'],
    ['fc00::/7', 'Unique local address (private)'],
    ['fe80::/10', 'Link-local'],
    ['ff00::/8', 'Multicast'],
  ] as const
).map(([cidr, label]) => ({ range: parseCidr(cidr)!, label }));

/** Returns why an address is internal/reserved, or null for public addresses. */
export function internalIpReason(ip: ParsedIp): string | null {
  return INTERNAL_RANGES.find((r) => inRange(ip, r.range))?.label ?? null;
}

/** DNSBL query label: reversed octets (IPv4) or reversed nibbles (IPv6). */
export function reverseIpForDnsbl(ip: ParsedIp): string {
  if (ip.version === 4) return ip.address.split('.').reverse().join('.');
  return ip.value.toString(16).padStart(32, '0').split('').reverse().join('.');
}
