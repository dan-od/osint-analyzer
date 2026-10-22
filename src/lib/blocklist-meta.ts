// Which blocklists we query. Plain data, safe to import in the browser; the
// lookup code lives in lib/server/blocklists.
//
// DNSBLs were chosen after testing every zone against its RFC 5782 test points
// (Oct 2026). Deliberately left out: SORBS, NJABL, NiX Spam, WPBL, inps.de
// (shut down), AHBL (answers "listed" for every IP), SpamRATS (needs a key and
// blocks open resolvers), korea.services.net (lists a whole country),
// all.s5h.net (lists whole /24s), cbl.abuseat.org (now part of Spamhaus ZEN),
// bl.blocklist.de (we load the blocklist.de feed directly).
import type { BlocklistTrust } from '@/types';

export interface DnsblMeta {
  id: string;
  name: string;
  zone: string;
  trust: BlocklistTrust;
  ipv6?: boolean;
}

export interface FeedMeta {
  id: string;
  name: string;
  url: string;
  trust: BlocklistTrust;
}

export const IP_DNSBL_META: DnsblMeta[] = [
  { id: 'spamhaus-zen', name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', trust: 'high', ipv6: true },
  { id: 'spamcop', name: 'SpamCop', zone: 'bl.spamcop.net', trust: 'medium', ipv6: true },
  { id: 'barracuda', name: 'Barracuda', zone: 'b.barracudacentral.org', trust: 'medium', ipv6: true },
  { id: 'psbl', name: 'PSBL', zone: 'psbl.surriel.com', trust: 'medium' },
  { id: 'dronebl', name: 'DroneBL', zone: 'dnsbl.dronebl.org', trust: 'medium', ipv6: true },
  { id: 'mailspike-bl', name: 'Mailspike BL', zone: 'bl.mailspike.net', trust: 'medium' },
  { id: 'mailspike-z', name: 'Mailspike Z', zone: 'z.mailspike.net', trust: 'medium', ipv6: true },
  { id: 'gbudb', name: 'GBUdb Truncate', zone: 'truncate.gbudb.net', trust: 'medium' },
  { id: 'uceprotect-1', name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net', trust: 'low', ipv6: true },
  { id: 'uceprotect-2', name: 'UCEPROTECT L2', zone: 'dnsbl-2.uceprotect.net', trust: 'noisy' },
  { id: 'uceprotect-3', name: 'UCEPROTECT L3', zone: 'dnsbl-3.uceprotect.net', trust: 'noisy' },
  { id: 'spfbl', name: 'SPFBL', zone: 'dnsbl.spfbl.net', trust: 'low', ipv6: true },
  { id: '0spam', name: '0spam', zone: 'bl.0spam.org', trust: 'low' },
  { id: 'interserver', name: 'InterServer RBL', zone: 'rbl.interserver.net', trust: 'low', ipv6: true },
  { id: 'nordspam', name: 'NordSpam', zone: 'bl.nordspam.com', trust: 'low', ipv6: true },
  { id: 'anonmails', name: 'Anonmails', zone: 'spam.dnsbl.anonmails.de', trust: 'low' },
  { id: 'suomispam', name: 'SuomiSpam', zone: 'bl.suomispam.net', trust: 'low' },
  { id: 'sem-bl', name: 'SpamEatingMonkey', zone: 'bl.spameatingmonkey.net', trust: 'low' },
  { id: 'swinog', name: 'SWINOG', zone: 'dnsrbl.swinog.ch', trust: 'low' },
  { id: 'justspam', name: 'JustSpam', zone: 'dnsbl.justspam.org', trust: 'noisy', ipv6: true },
  { id: 'backscatterer', name: 'Backscatterer', zone: 'ips.backscatterer.org', trust: 'noisy' },
];

export const DOMAIN_DNSBL_META: DnsblMeta[] = [
  { id: 'spamhaus-dbl', name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', trust: 'high' },
  { id: 'surbl', name: 'SURBL', zone: 'multi.surbl.org', trust: 'medium' },
  { id: 'uribl', name: 'URIBL', zone: 'multi.uribl.com', trust: 'medium' },
  { id: 'sem-uribl', name: 'SpamEatingMonkey URI', zone: 'uribl.spameatingmonkey.net', trust: 'low' },
  { id: 'nordspam-dbl', name: 'NordSpam DBL', zone: 'dbl.nordspam.com', trust: 'low' },
  { id: 'suomispam-dbl', name: 'SuomiSpam DBL', zone: 'dbl.suomispam.net', trust: 'low' },
];

export const FEED_META: FeedMeta[] = [
  // Informational: Tor exits relay traffic for many people, but are a common source of abuse
  { id: 'tor-exits', name: 'Tor exit nodes', url: 'https://check.torproject.org/torbulkexitlist', trust: 'low' },
  { id: 'feodo', name: 'Feodo Tracker (botnet C2)', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', trust: 'high' },
  { id: 'blocklist-de', name: 'blocklist.de', url: 'https://lists.blocklist.de/lists/all.txt', trust: 'medium' },
  { id: 'cins', name: 'CINS Army', url: 'https://cinsscore.com/list/ci-badguys.txt', trust: 'medium' },
  {
    id: 'firehol-level1',
    name: 'FireHOL Level 1',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    trust: 'medium',
  },
];

/** Threat-intel APIs and feeds that count toward blocklist coverage, with their trust */
export const API_BLOCKLIST_TRUST: Record<string, { name: string; trust: BlocklistTrust }> = {
  urlhaus: { name: 'URLhaus', trust: 'high' },
  threatfox: { name: 'ThreatFox', trust: 'high' },
  'google-safe-browsing': { name: 'Google Safe Browsing', trust: 'high' },
  otx: { name: 'AlienVault OTX', trust: 'medium' },
  phishtank: { name: 'PhishTank', trust: 'medium' },
  openphish: { name: 'OpenPhish', trust: 'medium' },
};
