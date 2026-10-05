// ============================================
// DOMAIN ANALYSIS - every source runs in parallel as its own task
// ============================================
import type { AnalysisResult, BlocklistCoverage, BlocklistSourceResult, Indicator } from '@/types';
import {
  performDnsLookup,
  checkAbuseIPDB,
  checkWhois,
  checkVirusTotal,
  checkGoogleSafeBrowsing,
  checkPhishStats,
  checkOpenPhish,
  hasSuspiciousTLD,
  checkTyposquatting,
  type AbuseIPDBResult,
  type DnsResult,
  type GoogleSafeBrowsingResult,
  type PhishStatsResult,
  type VirusTotalResult,
  type WhoisResult,
} from '@/lib/osint-apis';
import { internalIpReason, parseIp } from '@/lib/ip';
import { API_BLOCKLIST_TRUST, IP_DNSBL_META } from '@/lib/blocklist-meta';
import {
  coverageDetail,
  coverageIndicator,
  domainBlocklistCoverage,
  DOMAIN_COVERAGE_SOURCE_COUNT,
  dqsKey,
  summarizeCoverage,
} from '../blocklists';
import { checkIpDnsbls } from '../blocklists/dnsbl';
import { cdnForIp } from '../cdn';
import type { AnalysisContext } from './context';
import { TaskRunner } from './tasks';
import { buildResult } from './scoring';
import { pivotsFor, withFacts } from './facts';
import { domainAgeIndicator } from './email';
import { abuseIpdbDetail, abuseIpdbIndicator, virusTotalDetail, virusTotalIndicator } from './shared';

/** The first public A record, if any */
function hostingIp(dns: DnsResult | null) {
  const ip = dns?.a.length ? parseIp(dns.a[0]) : null;
  return ip && !internalIpReason(ip) ? ip : null;
}

export async function analyzeDomain(domain: string, ctx: AnalysisContext): Promise<AnalysisResult> {
  const runner = new TaskRunner(ctx);
  let cdn: string | null = null;

  runner.add<DnsResult>({
    id: 'dns',
    label: 'DNS resolution',
    source: 'DNS lookup',
    run: () => performDnsLookup(domain),
    build: (dns, out) => {
      const first = dns.a[0];
      cdn = first ? cdnForIp(first) : null;
      out.indicators.push({
        id: 'dns-resolution',
        name: 'DNS resolution',
        status: first ? 'pass' : 'fail',
        description: first
          ? `Resolves to ${dns.a.join(', ')}.${cdn ? ` This is a ${cdn} address, so IP-level checks describe ${cdn}, not this site.` : ''}`
          : 'Does not resolve to any IP address.',
        severity: first ? 'low' : 'critical',
        source: 'DNS lookup',
      });
      out.details.dns = {
        title: `DNS, ${domain}`,
        data: {
          A: dns.a.join(', ') || 'none',
          ...(cdn ? { CDN: cdn } : {}),
          MX: dns.mx.map((m) => m.exchange).join(', ') || 'none',
          NS: dns.ns.join(', ') || 'none',
          SPF: dns.spf || 'missing',
          DMARC: dns.dmarc || 'missing',
        },
        status: first ? 'pass' : 'fail',
      };
    },
  });

  runner.add<WhoisResult>({
    id: 'whois',
    label: 'Domain age',
    source: 'WHOIS',
    serverKeyEnv: 'WHOISXML_API_KEY',
    // WhoisXML only has a shared server key (500/month); bulk jobs would burn through it
    skip: ctx.mode === 'bulk' ? 'Not run in bulk jobs (shared WHOIS quota).' : undefined,
    run: () => checkWhois(domain),
    build: (whois, out) => {
      out.indicators.push(domainAgeIndicator(whois));
      out.details.whois = {
        title: `WHOIS, ${domain}`,
        data: {
          registrar: whois.registrar || 'unknown',
          created: whois.creationDate?.slice(0, 10) || 'unknown',
          expires: whois.expirationDate?.slice(0, 10) || 'unknown',
          age: whois.domainAge !== null ? `${whois.domainAge} days` : 'unknown',
        },
        status: whois.isNewDomain ? 'warning' : 'pass',
      };
    },
  });

  runner.add<VirusTotalResult>({
    id: 'virustotal',
    label: 'VirusTotal',
    source: 'VirusTotal',
    service: 'virustotal',
    run: ({ key }) => checkVirusTotal(domain, 'domain', key!),
    build: (vt, out) => {
      out.indicators.push(virusTotalIndicator(vt, 'domain'));
      out.details.virustotal = virusTotalDetail(vt, 'domain');
    },
  });

  runner.add<GoogleSafeBrowsingResult>({
    id: 'safe-browsing',
    label: 'Safe Browsing',
    source: 'Google',
    serverKeyEnv: 'GOOGLE_SAFE_BROWSING_API_KEY',
    run: () => checkGoogleSafeBrowsing(`https://${domain}`),
    build: (gsb, out) => {
      out.indicators.push({
        id: 'safe-browsing',
        name: 'Safe Browsing',
        status: gsb.isMalicious ? 'fail' : 'pass',
        description: gsb.isMalicious ? `Flagged as ${gsb.threats.join(', ').toLowerCase().replace(/_/g, ' ')}.` : 'Not flagged.',
        severity: gsb.isMalicious ? 'critical' : 'low',
        source: 'Google',
      });
    },
  });

  runner.add<PhishStatsResult>({
    id: 'phishstats',
    label: 'PhishStats',
    source: 'PhishStats',
    run: () => checkPhishStats(domain),
    build: (ps, out) => {
      out.indicators.push({
        id: 'phishstats',
        name: 'PhishStats',
        status: ps.found ? 'fail' : 'pass',
        description: ps.found ? `In the phishing database (score ${ps.phishScore}).` : 'Not in the phishing database.',
        severity: ps.found ? 'critical' : 'low',
        source: 'PhishStats',
      });
    },
  });

  runner.add<{ found: boolean; url?: string }>({
    id: 'openphish',
    label: 'OpenPhish',
    source: 'OpenPhish',
    run: () => checkOpenPhish(domain),
    build: (op, out) => {
      out.indicators.push({
        id: 'openphish',
        name: 'OpenPhish',
        status: op.found ? 'fail' : 'pass',
        description: op.found ? 'In the OpenPhish phishing feed.' : 'Not in feed.',
        severity: op.found ? 'critical' : 'low',
        source: 'OpenPhish',
      });
    },
  });

  runner.add<BlocklistCoverage>({
    id: 'blocklists',
    label: 'Blocklist coverage',
    source: 'DNSBLs, abuse.ch, OTX',
    sources: DOMAIN_COVERAGE_SOURCE_COUNT,
    selfReport: true,
    run: async ({ report, wait }) => {
      const coverage = await domainBlocklistCoverage(domain, ctx, [], report);
      // Fold in the feeds the domain analyzer checks itself
      const [gsb, openphish, phishstats] = await Promise.all([
        wait<GoogleSafeBrowsingResult>('safe-browsing'),
        wait<{ found: boolean }>('openphish'),
        wait<PhishStatsResult>('phishstats'),
      ]);
      const existing: BlocklistSourceResult[] = [];
      const add = (id: keyof typeof API_BLOCKLIST_TRUST, listed: boolean | undefined) => {
        if (listed !== undefined) existing.push({ id, kind: 'api', ...API_BLOCKLIST_TRUST[id], status: listed ? 'listed' : 'clean' });
      };
      add('google-safe-browsing', gsb?.isMalicious);
      add('openphish', openphish?.found);
      add('phishstats', phishstats?.found);
      return summarizeCoverage([...coverage.sources, ...existing]);
    },
    build: (coverage, out) => {
      out.indicators.push(coverageIndicator(coverage));
      out.details.blocklists = coverageDetail(coverage);
    },
  });

  runner.add<AbuseIPDBResult>({
    id: 'abuseipdb',
    label: 'Abuse reports',
    source: 'AbuseIPDB',
    service: 'abuseipdb',
    run: async ({ key, wait }) => {
      const ip = hostingIp(await wait<DnsResult>('dns'));
      return ip ? checkAbuseIPDB(ip.address, key!) : null;
    },
    build: (abuse, out) => {
      const isCdn = cdn ?? (abuse.usageType === 'Content Delivery Network' ? abuse.isp || 'a CDN' : null);
      out.indicators.push(abuseIpdbIndicator(abuse, isCdn));
      out.details.abuseipdb = abuseIpdbDetail(abuse);
    },
    onEmpty: (out) => {
      out.answered = false;
      out.indicators.push({
        id: 'skipped-abuseipdb',
        name: 'Abuse reports',
        status: 'unknown',
        description: 'No public IP address to check.',
        severity: 'low',
        source: 'AbuseIPDB',
      });
    },
  });

  runner.add<{ ip: string; coverage: BlocklistCoverage } | null>({
    id: 'hosting-dnsbl',
    label: 'Hosting IP blocklists',
    source: 'DNSBLs',
    sources: IP_DNSBL_META.length,
    selfReport: true,
    run: async ({ report, wait }) => {
      const ip = hostingIp(await wait<DnsResult>('dns'));
      if (!ip) return null;
      const key = await dqsKey(ctx);
      const results = await checkIpDnsbls(ip, {
        spamhausDqsKey: key,
        onResult: (r) => report(r.status === 'listed' || r.status === 'clean'),
      });
      return { ip: ip.address, coverage: summarizeCoverage(results) };
    },
    build: (value, out) => {
      if (!value) return;
      const { ip, coverage } = value;
      if (coverage.checked === 0) return;
      const listedOn = coverage.sources.filter((r) => r.status === 'listed').map((r) => r.name);
      // Hosting IPs are often shared (or a CDN), so a listing here is a warning, not proof
      out.indicators.push({
        id: 'ip-blacklists',
        name: 'Hosting IP blocklists',
        status: listedOn.length > 0 ? 'warning' : 'pass',
        description:
          listedOn.length > 0
            ? `${ip} is on ${listedOn.length} of ${coverage.checked} DNSBLs: ${listedOn.join(', ')}.${cdn ? ` It is a ${cdn} address shared with many sites.` : ''}`
            : `${ip} is not on any of ${coverage.checked} DNSBLs.`,
        severity: coverage.weightedScore >= 35 && !cdn ? 'high' : listedOn.length > 0 ? 'medium' : 'low',
        source: 'DNSBLs',
      });
    },
    onEmpty: (out) => {
      out.answered = false;
      out.indicators.push({
        id: 'skipped-hosting-dnsbl',
        name: 'Hosting IP blocklists',
        status: 'unknown',
        description: 'No public IP address to check.',
        severity: 'low',
        source: 'DNSBLs',
      });
    },
  });

  runner.add<Indicator[]>({
    id: 'rules',
    label: 'Look-alike and TLD rules',
    source: 'Rules',
    sources: 0,
    run: async () => {
      const found: Indicator[] = [];
      if (hasSuspiciousTLD(domain)) {
        found.push({
          id: 'suspicious-tld',
          name: 'Suspicious TLD',
          status: 'warning',
          description: 'Uses a TLD commonly associated with spam and phishing.',
          severity: 'medium',
          source: 'TLD rules',
        });
      }
      const typo = checkTyposquatting(domain);
      if (typo.isTyposquat) {
        found.push({
          id: 'typosquatting',
          name: 'Look-alike domain',
          status: 'fail',
          description: `Looks like an imitation of "${typo.targetBrand}"${typo.similarity ? ` (${Math.round(typo.similarity * 100)}% similar)` : ''}.`,
          severity: 'critical',
          source: 'Look-alike rules',
        });
      }
      return found;
    },
    build: (found, out) => out.indicators.push(...found),
  });

  await runner.run(domain, 'domain', pivotsFor('domain', domain));
  const { indicators, details } = runner.collect();
  const coverage = runner.value<BlocklistCoverage>('blocklists');
  const abuse = runner.value<AbuseIPDBResult>('abuseipdb');
  const vt = runner.value<VirusTotalResult>('virustotal');

  const result = buildResult('domain', domain, indicators, details, ctx);
  return withFacts(
    { ...result, ...(coverage ? { blocklist: coverage } : {}), pivots: pivotsFor('domain', domain, abuse?.ipAddress) },
    {
      abuseScore: abuse?.abuseConfidenceScore ?? null,
      vtDetections: vt ? `${vt.positives}/${vt.total}` : null,
      proxyType: null,
      country: abuse?.countryCode ?? null,
    }
  );
}
