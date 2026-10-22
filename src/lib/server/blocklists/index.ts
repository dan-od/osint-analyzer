// Free blocklist aggregator (URLVoid/IPVoid-style, without scraping):
// DNSBLs + daily feeds + abuse.ch/OTX/PhishTank, summarized with trust weights.
import type { BlocklistCoverage, BlocklistSourceResult } from '@/types';
import type { ParsedIp } from '@/lib/ip';
import { API_BLOCKLIST_TRUST, DOMAIN_DNSBL_META, FEED_META, IP_DNSBL_META } from '@/lib/blocklist-meta';
import type { AnalysisContext } from '../analysis/context';
import { checkDomainDnsbls, checkIpDnsbls } from './dnsbl';
import { checkIpFeeds } from './feeds';
import { keyedSource, summarizeCoverage } from './coverage';
import { checkOtx, checkPhishTank, checkThreatFox, checkUrlhausHost } from '../sources/threat-intel';

export { coverageDetail, coverageIndicator, summarizeCoverage } from './coverage';

/** Called once per source as it answers; true when the answer was usable */
export type SourceReporter = (answered: boolean) => void;

const usable = (r: BlocklistSourceResult) => r.status === 'listed' || r.status === 'clean';

function tap(onSource?: SourceReporter) {
  return (r: BlocklistSourceResult) => {
    onSource?.(usable(r));
    return r;
  };
}

/** The user's (or server's) Spamhaus DQS key, if any. Each DNSBL query counts as one use. */
export async function dqsKey(ctx: AnalysisContext): Promise<string | null> {
  if (!ctx.keys.hasKey('spamhaus_dqs')) return null;
  const grant = await ctx.keys.acquire('spamhaus_dqs');
  return grant.ok ? grant.key : null;
}

export function ipDnsblCount(ip: ParsedIp): number {
  return IP_DNSBL_META.filter((m) => ip.version === 4 || m.ipv6).length;
}

/** DNSBLs + feeds + URLhaus, ThreatFox, OTX */
export function ipCoverageSourceCount(ip: ParsedIp): number {
  return ipDnsblCount(ip) + FEED_META.length + 3;
}

/** Domain DNSBLs + URLhaus, ThreatFox, OTX, PhishTank */
export const DOMAIN_COVERAGE_SOURCE_COUNT = DOMAIN_DNSBL_META.length + 4;

export async function ipBlocklistCoverage(
  ip: ParsedIp,
  ctx: AnalysisContext,
  onSource?: SourceReporter
): Promise<BlocklistCoverage> {
  const target = ip.address;
  const report = tap(onSource);
  const groups = await Promise.all([
    dqsKey(ctx).then((key) => checkIpDnsbls(ip, { spamhausDqsKey: key, onResult: report })),
    checkIpFeeds(ip, report),
    Promise.all([
      keyedSource(ctx, 'abusech', { id: 'urlhaus', ...API_BLOCKLIST_TRUST.urlhaus }, (key) => checkUrlhausHost(target, key)).then(report),
      keyedSource(ctx, 'abusech', { id: 'threatfox', ...API_BLOCKLIST_TRUST.threatfox }, (key) => checkThreatFox(target, key)).then(report),
      keyedSource(ctx, 'otx', { id: 'otx', ...API_BLOCKLIST_TRUST.otx }, (key) =>
        checkOtx(ip.version === 4 ? 'IPv4' : 'IPv6', target, key)
      ).then(report),
    ]),
  ]);
  return summarizeCoverage(groups.flat());
}

/**
 * Domain coverage. `existing` carries results the domain analyzer already
 * fetched (Google Safe Browsing, OpenPhish) so they're counted too.
 */
export async function domainBlocklistCoverage(
  domain: string,
  ctx: AnalysisContext,
  existing: BlocklistSourceResult[] = [],
  onSource?: SourceReporter
): Promise<BlocklistCoverage> {
  const report = tap(onSource);
  const groups = await Promise.all([
    dqsKey(ctx).then((key) => checkDomainDnsbls(domain, { spamhausDqsKey: key, onResult: report })),
    Promise.all([
      keyedSource(ctx, 'abusech', { id: 'urlhaus', ...API_BLOCKLIST_TRUST.urlhaus }, (key) => checkUrlhausHost(domain, key)).then(report),
      keyedSource(ctx, 'abusech', { id: 'threatfox', ...API_BLOCKLIST_TRUST.threatfox }, (key) => checkThreatFox(domain, key)).then(report),
      keyedSource(ctx, 'otx', { id: 'otx', ...API_BLOCKLIST_TRUST.otx }, (key) => checkOtx('domain', domain, key)).then(report),
      checkPhishTank(domain)
        .then((r): BlocklistSourceResult => ({ id: 'phishtank', kind: 'api', ...API_BLOCKLIST_TRUST.phishtank, ...r }))
        .then(report),
    ]),
  ]);
  return summarizeCoverage([...groups.flat(), ...existing]);
}
