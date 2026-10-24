// Every external source the analyzers query, in one place. All the numbers
// in the UI copy ("57 sources", "21 DNS blocklists", per-type counts) are
// derived from this list so they can't drift from the code.
//
// Counting rule: each DNS blocklist zone and each downloaded feed is its own
// source (they're run by different people and answer independently). Local
// rule sets (disposable domains, suspicious TLDs, look-alike patterns,
// phone-number patterns) are not counted.
import type { AnalysisType } from '@/types';
import type { ServiceId } from './services';
import { DOMAIN_DNSBL_META, FEED_META, IP_DNSBL_META } from './blocklist-meta';

export type SourceKind = 'api' | 'dns' | 'dnsbl' | 'feed' | 'database';

export interface SourceEntry {
  id: string;
  name: string;
  kind: SourceKind;
  types: AnalysisType[];
  /** Needs a key the user can add in Settings */
  service?: ServiceId;
  /** Needs a key only the server admin can configure */
  serverKeyEnv?: string;
}

const API_SOURCES: SourceEntry[] = [
  { id: 'google-dns', name: 'DNS (Google Public DNS)', kind: 'dns', types: ['email', 'domain'] },
  { id: 'whois', name: 'RDAP / WHOIS registration data', kind: 'api', types: ['email', 'domain'] },
  { id: 'virustotal', name: 'VirusTotal', kind: 'api', types: ['ip', 'domain'], service: 'virustotal' },
  { id: 'abuseipdb', name: 'AbuseIPDB', kind: 'api', types: ['ip', 'domain'], service: 'abuseipdb' },
  { id: 'greynoise', name: 'GreyNoise', kind: 'api', types: ['ip'], service: 'greynoise' },
  { id: 'internetdb', name: 'Shodan InternetDB', kind: 'api', types: ['ip'] },
  { id: 'ip2proxy', name: 'IP2Proxy LITE', kind: 'database', types: ['ip'] },
  { id: 'google-safe-browsing', name: 'Google Safe Browsing', kind: 'api', types: ['domain'], serverKeyEnv: 'GOOGLE_SAFE_BROWSING_API_KEY' },
  { id: 'openphish', name: 'OpenPhish', kind: 'feed', types: ['domain'] },
  { id: 'phishtank', name: 'PhishTank', kind: 'api', types: ['domain'] },
  { id: 'urlhaus', name: 'URLhaus', kind: 'api', types: ['ip', 'domain'], service: 'abusech' },
  { id: 'threatfox', name: 'ThreatFox', kind: 'api', types: ['ip', 'domain'], service: 'abusech' },
  { id: 'otx', name: 'AlienVault OTX', kind: 'api', types: ['ip', 'domain'], service: 'otx' },
  { id: 'emailrep', name: 'EmailRep', kind: 'api', types: ['email'] },
  { id: 'hunter', name: 'Hunter.io', kind: 'api', types: ['email'], service: 'hunter' },
  { id: 'ipqs', name: 'IPQualityScore', kind: 'api', types: ['email', 'phone'], service: 'ipqs' },
  { id: 'hibp', name: 'Have I Been Pwned', kind: 'api', types: ['email'], service: 'hibp' },
  { id: 'numverify', name: 'NumVerify', kind: 'api', types: ['phone'], serverKeyEnv: 'NUMVERIFY_API_KEY' },
  { id: 'blockchain-info', name: 'Blockchain.info', kind: 'api', types: ['crypto'] },
  { id: 'etherscan', name: 'Etherscan', kind: 'api', types: ['crypto'] },
  { id: 'chainabuse', name: 'ChainAbuse', kind: 'api', types: ['crypto'] },
  { id: 'btc-black', name: 'BTC Black', kind: 'dnsbl', types: ['crypto'] },
  { id: 'opensanctions', name: 'OpenSanctions', kind: 'api', types: ['crypto'] },
  { id: 'chainalysis', name: 'Chainalysis sanctions', kind: 'api', types: ['crypto'], serverKeyEnv: 'CHAINALYSIS_API_KEY' },
  { id: 'github-scam-lists', name: 'GitHub scam lists', kind: 'feed', types: ['crypto'] },
];

export const SOURCES: SourceEntry[] = [
  ...API_SOURCES,
  // IP blocklists also run on the address a domain resolves to
  ...IP_DNSBL_META.map((m): SourceEntry => ({ id: m.id, name: m.name, kind: 'dnsbl', types: ['ip', 'domain'] })),
  ...DOMAIN_DNSBL_META.map((m): SourceEntry => ({
    id: m.id,
    name: m.name,
    kind: 'dnsbl',
    // Email checks look the sender's domain up on Spamhaus DBL
    types: m.id === 'spamhaus-dbl' ? ['domain', 'email'] : ['domain'],
  })),
  ...FEED_META.map((m): SourceEntry => ({ id: m.id, name: m.name, kind: 'feed', types: ['ip'] })),
];

export const SOURCE_COUNT = SOURCES.length;
export const IP_DNSBL_COUNT = IP_DNSBL_META.length;
export const DOMAIN_DNSBL_COUNT = DOMAIN_DNSBL_META.length;
export const FEED_COUNT = FEED_META.length;

export function sourcesFor(type: AnalysisType): SourceEntry[] {
  return SOURCES.filter((s) => s.types.includes(type));
}

export function sourceCountFor(type: AnalysisType): number {
  return sourcesFor(type).length;
}

export function sourceName(id: string): string {
  return SOURCES.find((s) => s.id === id)?.name ?? id;
}

/** Sources that work with no key at all */
export const KEYLESS_SOURCE_COUNT = SOURCES.filter((s) => !s.service && !s.serverKeyEnv).length;
