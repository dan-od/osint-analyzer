// DNS blocklist (DNSBL / URIBL) lookups, run in parallel with a 2 s timeout each.
// Which lists, and why, is in lib/blocklist-meta.ts.
import { promises as dns } from 'dns';
import { reverseIpForDnsbl, type ParsedIp } from '@/lib/ip';
import type { BlocklistSourceResult, BlocklistTrust } from '@/types';
import { DOMAIN_DNSBL_META, IP_DNSBL_META } from '@/lib/blocklist-meta';
import { DNSBL_TIMEOUT_SECONDS } from '@/lib/bulk-limits';

const QUERY_TIMEOUT_MS = DNSBL_TIMEOUT_SECONDS * 1000;

type Decision = { status: 'listed' | 'clean' | 'refused'; detail?: string };

interface DnsblZone {
  id: string;
  name: string;
  zone: string;
  trust: BlocklistTrust;
  ipv6?: boolean;
  /** Interprets the A records returned for a listed name */
  decode?: (answers: string[]) => Decision;
}

const lastOctet = (a: string) => Number(a.split('.')[3]);

const SPAMHAUS_ZEN_CODES: Record<string, string> = {
  '127.0.0.2': 'SBL (spam source)',
  '127.0.0.3': 'CSS (snowshoe spam)',
  '127.0.0.4': 'XBL (exploited / infected host)',
  '127.0.0.5': 'XBL (exploited / infected host)',
  '127.0.0.6': 'XBL (exploited / infected host)',
  '127.0.0.7': 'XBL (exploited / infected host)',
  '127.0.0.9': 'DROP (hijacked / criminal netblock)',
  '127.0.0.10': 'PBL (end-user range, ISP policy)',
  '127.0.0.11': 'PBL (end-user range, Spamhaus policy)',
  '127.0.0.30': 'BCL (botnet controller)',
};

const SPAMHAUS_DBL_CODES: Record<string, string> = {
  '127.0.1.2': 'spam domain',
  '127.0.1.4': 'phishing domain',
  '127.0.1.5': 'malware domain',
  '127.0.1.6': 'botnet C&C domain',
  '127.0.1.102': 'abused legit domain (spam)',
  '127.0.1.103': 'abused legit domain (spammed redirector)',
  '127.0.1.104': 'abused legit domain (phishing)',
  '127.0.1.105': 'abused legit domain (malware)',
  '127.0.1.106': 'abused legit domain (botnet C&C)',
};

function decodeSpamhausZen(answers: string[]): Decision {
  const meanings = answers.map((a) => SPAMHAUS_ZEN_CODES[a] ?? a);
  // PBL only says "this is a residential/dynamic range" – not evidence of abuse
  const policyOnly = answers.every((a) => a === '127.0.0.10' || a === '127.0.0.11');
  return policyOnly
    ? { status: 'clean', detail: `${meanings.join(', ')} – policy listing, not abuse` }
    : { status: 'listed', detail: meanings.filter((m) => !m.startsWith('PBL')).join(', ') };
}

function decodeSpamhausDbl(answers: string[]): Decision {
  return { status: 'listed', detail: answers.map((a) => SPAMHAUS_DBL_CODES[a] ?? a).join(', ') };
}

// SURBL and URIBL answer 127.0.0.1 when they refuse a resolver
function decodeSurbl(answers: string[]): Decision {
  const code = lastOctet(answers[0]);
  if (code === 1) return { status: 'refused', detail: 'SURBL refused this DNS resolver' };
  const lists = [
    [4, 'DM (disposable/malicious)'], [8, 'PH (phishing)'], [16, 'MW (malware)'],
    [32, 'CT (click tracker)'], [64, 'ABUSE'], [128, 'CR (cracked site)'],
  ] as const;
  const hits = lists.filter(([bit]) => code & bit).map(([, label]) => label);
  return { status: 'listed', detail: hits.join(', ') || `code ${code}` };
}

function decodeUribl(answers: string[]): Decision {
  const code = lastOctet(answers[0]);
  if (code === 1) return { status: 'refused', detail: 'URIBL refused this DNS resolver' };
  if (code === 255) return { status: 'refused', detail: 'URIBL query limit exceeded' };
  const black = code & 2;
  const red = code & 8;
  const grey = code & 4;
  if (!black && !red) {
    return { status: 'clean', detail: grey ? 'grey list only (bulk sender, not abuse)' : undefined };
  }
  return { status: 'listed', detail: [black && 'black', red && 'red', grey && 'grey'].filter(Boolean).join(', ') };
}

function decodeMailspike(answers: string[]): Decision {
  // 127.0.0.2 is the blocklist; 127.0.0.10–20 are reputation levels
  return answers.includes('127.0.0.2')
    ? { status: 'listed' }
    : { status: 'clean', detail: 'reputation score only' };
}

const IP_DECODERS: Record<string, DnsblZone['decode']> = { 'spamhaus-zen': decodeSpamhausZen, 'mailspike-bl': decodeMailspike };
export const IP_DNSBLS: DnsblZone[] = IP_DNSBL_META.map((m) => ({ ...m, decode: IP_DECODERS[m.id] }));

const DOMAIN_DECODERS: Record<string, DnsblZone['decode']> = { 'spamhaus-dbl': decodeSpamhausDbl, 'surbl': decodeSurbl, 'uribl': decodeUribl };
export const DOMAIN_DNSBLS: DnsblZone[] = DOMAIN_DNSBL_META.map((m) => ({ ...m, decode: DOMAIN_DECODERS[m.id] }));

const REFUSAL_REASONS: Record<string, string> = {
  '127.255.255.250': 'query refused (Spamhaus DQS key disabled)',
  '127.255.255.251': 'query refused (Spamhaus DQS key not valid for this use)',
  '127.255.255.252': 'query refused (typo in list name)',
  '127.255.255.254': 'query refused (public/open DNS resolver – add a Spamhaus DQS key)',
  '127.255.255.255': 'query refused (too many queries)',
};

let resolver: dns.Resolver | null = null;
function getResolver(): dns.Resolver {
  if (!resolver) {
    resolver = new dns.Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 1 });
    // Optional dedicated resolver(s). Public resolvers (8.8.8.8, 1.1.1.1, …) get
    // refused by Spamhaus, URIBL and SURBL, so prefer your own or the ISP's.
    const servers = process.env.DNSBL_RESOLVERS?.split(',').map((s) => s.trim()).filter(Boolean);
    if (servers?.length) resolver.setServers(servers);
  }
  return resolver;
}

async function lookup(name: string): Promise<{ answers: string[] } | { error: string }> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<{ error: string }>((resolve) => {
    timer = setTimeout(() => resolve({ error: 'timed out' }), QUERY_TIMEOUT_MS);
  });
  const query = getResolver()
    .resolve4(name)
    .then((answers) => ({ answers }))
    .catch((err: NodeJS.ErrnoException) =>
      err.code === 'ENOTFOUND' || err.code === 'ENODATA' ? { answers: [] } : { error: err.code ?? 'DNS error' }
    );
  try {
    return await Promise.race([query, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function queryZone(list: DnsblZone, label: string, zone: string): Promise<BlocklistSourceResult> {
  const base = { id: list.id, name: list.name, kind: 'dnsbl' as const, trust: list.trust };
  const result = await lookup(`${label}.${zone}`);
  if ('error' in result) return { ...base, status: 'error', detail: result.error };
  const { answers } = result;
  if (answers.length === 0) return { ...base, status: 'clean' };

  // 127.255.255.x = "query refused" (public resolver, bad key, rate limit). Never a listing.
  const refusal = answers.find((a) => a.startsWith('127.255.255.'));
  if (refusal) return { ...base, status: 'refused', detail: REFUSAL_REASONS[refusal] ?? `query refused (${refusal})` };
  // Real DNSBL answers are always in 127.0.0.0/8; anything else is DNS hijacking or a wildcard
  if (!answers.every((a) => a.startsWith('127.'))) {
    return { ...base, status: 'error', detail: `unexpected answer ${answers[0]}` };
  }
  const decision = list.decode ? list.decode(answers) : { status: 'listed' as const, detail: answers.join(', ') };
  return { ...base, ...decision };
}

export interface DnsblOptions {
  /** Spamhaus DQS key: queries <key>.zen/dbl.dq.spamhaus.net instead of the public mirror */
  spamhausDqsKey?: string | null;
  /** Restrict to these list ids */
  only?: string[];
  /** Called with each list's answer as it arrives */
  onResult?: (result: BlocklistSourceResult) => void;
}

function zoneFor(list: DnsblZone, options: DnsblOptions): string {
  const key = options.spamhausDqsKey;
  if (key && list.id === 'spamhaus-zen') return `${key}.zen.dq.spamhaus.net`;
  if (key && list.id === 'spamhaus-dbl') return `${key}.dbl.dq.spamhaus.net`;
  return list.zone;
}

export async function checkIpDnsbls(ip: ParsedIp, options: DnsblOptions = {}): Promise<BlocklistSourceResult[]> {
  const label = reverseIpForDnsbl(ip);
  return Promise.all(
    IP_DNSBLS.filter((list) => ip.version === 4 || list.ipv6).map((list) =>
      queryZone(list, label, zoneFor(list, options)).then((r) => {
        options.onResult?.(r);
        return r;
      })
    )
  );
}

export async function checkDomainDnsbls(domain: string, options: DnsblOptions = {}): Promise<BlocklistSourceResult[]> {
  // URI blocklists list registered domains; drop a leading "www."
  const label = domain.toLowerCase().replace(/^www\./, '');
  const lists = options.only ? DOMAIN_DNSBLS.filter((l) => options.only!.includes(l.id)) : DOMAIN_DNSBLS;
  return Promise.all(
    lists.map((list) =>
      queryZone(list, label, zoneFor(list, options)).then((r) => {
        options.onResult?.(r);
        return r;
      })
    )
  );
}
