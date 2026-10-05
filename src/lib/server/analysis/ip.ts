// ============================================
// IP ANALYSIS - every source runs in parallel as its own task
// ============================================
import type { AnalysisResult, BlocklistCoverage } from '@/types';
import { checkAbuseIPDB, checkVirusTotal, type AbuseIPDBResult, type VirusTotalResult } from '@/lib/osint-apis';
import { internalIpReason, parseIp, type ParsedIp } from '@/lib/ip';
import { checkGreyNoise, checkInternetDB, type GreyNoiseResult, type InternetDbResult } from '../sources/ip-intel';
import { checkIp2Proxy, isIp2ProxyAvailable, type Ip2ProxyResult } from '../sources/ip2proxy';
import { coverageDetail, coverageIndicator, ipBlocklistCoverage, ipCoverageSourceCount } from '../blocklists';
import { cdnForIp } from '../cdn';
import type { AnalysisContext } from './context';
import { TaskRunner } from './tasks';
import { buildResult } from './scoring';
import { pivotsFor, withFacts } from './facts';
import { abuseIpdbDetail, abuseIpdbIndicator, virusTotalDetail, virusTotalIndicator } from './shared';

const BAD_INTERNETDB_TAGS = new Set(['compromised', 'malware', 'c2', 'doublepulsar', 'botnet']);
const ANONYMIZER_TAGS = ['tor', 'vpn', 'proxy'];

const PROXY_NAMES: Record<string, string> = {
  VPN: 'VPN',
  TOR: 'Tor exit node',
  DCH: 'hosting provider / data center',
  PUB: 'public proxy',
  WEB: 'web proxy',
  SES: 'search engine robot',
  RES: 'residential proxy',
  CPN: 'consumer privacy network',
  EPN: 'enterprise private network',
};

export async function analyzeIp(input: string, ctx: AnalysisContext): Promise<AnalysisResult> {
  const ip = parseIp(input);
  if (!ip) throw new Error(`Not an IP address: ${input}`);

  // Private/reserved ranges never leave the server
  const internalReason = internalIpReason(ip);
  if (internalReason) return internalIpResult(ip, internalReason);

  const cdn = cdnForIp(ip.address);
  const runner = new TaskRunner(ctx);

  runner.add<AbuseIPDBResult>({
    id: 'abuseipdb',
    label: 'Abuse reports',
    source: 'AbuseIPDB',
    service: 'abuseipdb',
    run: ({ key }) => checkAbuseIPDB(ip.address, key!),
    build: (abuse, out) => {
      const isCdn = cdn ?? (abuse.usageType === 'Content Delivery Network' ? abuse.isp || 'a CDN' : null);
      out.indicators.push(abuseIpdbIndicator(abuse, isCdn));
      out.details.abuseipdb = abuseIpdbDetail(abuse);
    },
  });

  runner.add<VirusTotalResult>({
    id: 'virustotal',
    label: 'VirusTotal',
    source: 'VirusTotal',
    service: 'virustotal',
    run: ({ key }) => checkVirusTotal(ip.address, 'ip', key!),
    build: (vt, out) => {
      out.indicators.push(virusTotalIndicator(vt, 'ip'));
      out.details.virustotal = virusTotalDetail(vt, 'ip');
    },
  });

  // GreyNoise's community API is IPv4 only, so IPv6 doesn't spend quota on it
  if (ip.version === 4) {
    runner.add<GreyNoiseResult>({
      id: 'greynoise',
      label: 'Scanner noise',
      source: 'GreyNoise',
      service: 'greynoise',
      run: ({ key }) => checkGreyNoise(ip.address, key!),
      build: (gn, out) => {
        const base = { id: 'greynoise', name: 'Scanner noise', source: 'GreyNoise' };
        if (gn.riot) {
          out.indicators.push({ ...base, status: 'pass', severity: 'low', description: `Known benign service${gn.name ? `: ${gn.name}` : ''} (GreyNoise RIOT).` });
        } else if (gn.classification === 'malicious') {
          out.indicators.push({ ...base, status: 'fail', severity: 'high', description: 'Classified as malicious: seen scanning or attacking internet hosts.' });
        } else if (gn.noise) {
          out.indicators.push({
            ...base,
            status: gn.classification === 'benign' ? 'pass' : 'warning',
            severity: 'low',
            description: `Mass scanner (internet background noise), classified ${gn.classification || 'unknown'}${gn.name ? `, ${gn.name}` : ''}.`,
          });
        } else {
          out.indicators.push({ ...base, status: 'pass', severity: 'low', description: 'Not seen scanning the internet.' });
        }
        if (gn.found) {
          out.details.greynoise = {
            title: 'GreyNoise',
            data: { classification: gn.classification || 'unknown', noise: gn.noise, riot: gn.riot, name: gn.name || 'n/a', 'last seen': gn.lastSeen || 'n/a' },
            status: gn.classification === 'malicious' ? 'fail' : 'pass',
          };
        }
      },
    });
  }

  runner.add<InternetDbResult>({
    id: 'internetdb',
    label: 'Open ports and CVEs',
    source: 'Shodan',
    run: () => checkInternetDB(ip.address),
    build: (db, out) => {
      if (!db.found) {
        out.indicators.push({ id: 'internetdb', name: 'Open ports and CVEs', status: 'pass', severity: 'low', description: 'Not seen by Shodan scanners.', source: 'Shodan' });
        return;
      }
      const badTags = db.tags.filter((t) => BAD_INTERNETDB_TAGS.has(t));
      if (badTags.length > 0) {
        out.indicators.push({ id: 'internetdb-tags', name: 'Shodan tags', status: 'fail', severity: 'high', description: `Tagged by Shodan: ${badTags.join(', ')}.`, source: 'Shodan' });
      }
      out.indicators.push({
        id: 'internetdb',
        name: 'Open ports and CVEs',
        status: db.vulns.length > 0 ? 'warning' : 'pass',
        severity: db.vulns.length > 0 ? 'medium' : 'low',
        description:
          db.vulns.length > 0
            ? `${db.vulns.length} known CVE(s) on exposed services: ${db.vulns.slice(0, 5).join(', ')}${db.vulns.length > 5 ? '…' : ''}.`
            : `Open ports: ${db.ports.join(', ') || 'none'}. No known CVEs.`,
        source: 'Shodan',
      });
      out.details.internetdb = {
        title: 'Shodan InternetDB',
        data: { ports: db.ports.join(', ') || 'none', hostnames: db.hostnames.slice(0, 5).join(', ') || 'none', tags: db.tags.join(', ') || 'none', CVEs: db.vulns.length },
        status: badTags.length > 0 ? 'fail' : db.vulns.length > 0 ? 'warning' : 'pass',
      };
    },
  });

  // IP2Proxy LITE only runs when a local database file is installed
  if (isIp2ProxyAvailable()) {
    runner.add<Ip2ProxyResult>({
      id: 'ip2proxy',
      label: 'VPN / proxy',
      source: 'IP2Proxy',
      run: () => checkIp2Proxy(ip.address),
      build: (p, out) => {
        const type = p.proxyType;
        out.indicators.push({
          id: 'ip2proxy',
          name: 'VPN / proxy',
          status: p.isProxy ? 'warning' : 'pass',
          description: p.isProxy ? `Anonymizing service: ${type ? PROXY_NAMES[type] ?? type : 'proxy'}.` : 'Not listed as a proxy, VPN or Tor node.',
          severity: !p.isProxy ? 'low' : type === 'TOR' || type === 'PUB' || type === 'WEB' ? 'high' : type === 'VPN' ? 'medium' : 'low',
          source: 'IP2Proxy',
        });
        out.details.ip2proxy = {
          title: 'IP2Proxy LITE',
          data: { proxy: p.isProxy, type: type || 'none', 'usage type': p.usageType || 'n/a', threat: p.threat || 'n/a', database: p.database },
          status: p.isProxy ? 'warning' : 'pass',
        };
      },
    });
  }

  runner.add<BlocklistCoverage>({
    id: 'blocklists',
    label: 'Blocklist coverage',
    source: 'DNSBLs, feeds, abuse.ch, OTX',
    sources: ipCoverageSourceCount(ip),
    selfReport: true,
    run: ({ report }) => ipBlocklistCoverage(ip, ctx, report),
    build: (coverage, out) => {
      out.indicators.push(coverageIndicator(coverage));
      out.details.blocklists = coverageDetail(coverage);
    },
  });

  await runner.run(ip.address, 'ip', pivotsFor('ip', ip.address));
  const { indicators, details } = runner.collect();
  const abuse = runner.value<AbuseIPDBResult>('abuseipdb');
  const vt = runner.value<VirusTotalResult>('virustotal');
  const internetDb = runner.value<InternetDbResult>('internetdb');
  const ip2proxy = runner.value<Ip2ProxyResult>('ip2proxy');
  const coverage = runner.value<BlocklistCoverage>('blocklists');

  const anonymizerTag = internetDb?.tags.find((t) => ANONYMIZER_TAGS.includes(t));
  const isTorExit = !!coverage?.sources.some((s) => s.id === 'tor-exits' && s.status === 'listed');
  const result = buildResult('ip', ip.address, indicators, details, ctx);
  return withFacts(
    { ...result, ...(coverage ? { blocklist: coverage } : {}), pivots: pivotsFor('ip', ip.address) },
    {
      abuseScore: abuse?.abuseConfidenceScore ?? null,
      vtDetections: vt ? `${vt.positives}/${vt.total}` : null,
      proxyType: ip2proxy?.proxyType ?? (isTorExit ? 'TOR' : anonymizerTag ? anonymizerTag.toUpperCase() : null),
      country: abuse?.countryCode || vt?.country || ip2proxy?.countryCode || null,
    }
  );
}

function internalIpResult(ip: ParsedIp, reason: string): AnalysisResult {
  return {
    type: 'ip',
    query: ip.address,
    timestamp: new Date().toISOString(),
    riskScore: 0,
    riskLevel: 'low',
    confidence: 0,
    summary: `Internal IP – not checked. ${reason} addresses aren't routable on the public internet, so nothing was sent to any source.`,
    indicators: [
      {
        id: 'internal-ip',
        name: 'Internal address',
        status: 'unknown',
        description: `${reason}. Not checked.`,
        severity: 'low',
        source: 'IP classification',
      },
    ],
    details: {
      classification: {
        title: 'Address classification',
        data: { address: ip.address, version: `IPv${ip.version}`, range: reason },
        status: 'unknown',
      },
    },
    recommendations: ['Look this address up in your own network inventory, DHCP and firewall logs instead.'],
    sources: { answered: 0, total: 0 },
    facts: {
      verdict: 'Internal IP – not checked',
      abuseScore: null,
      vtDetections: null,
      blocklistHits: null,
      proxyType: null,
      country: null,
      topFinding: null,
    },
  };
}
