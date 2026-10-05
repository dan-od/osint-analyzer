// Finding builders shared by the IP and domain analyzers
import type { AnalysisDetail, Indicator } from '@/types';
import type { AbuseIPDBResult, VirusTotalResult } from '@/lib/osint-apis';

export function abuseIpdbIndicator(abuse: AbuseIPDBResult, cdn: string | null): Indicator {
  const score = abuse.abuseConfidenceScore;
  const cdnNote = cdn ? ` This address belongs to ${cdn}, so reports may be about other sites on it.` : '';
  return {
    id: 'abuse-reports',
    name: 'Abuse reports',
    status: score > 50 ? 'fail' : score > 10 ? 'warning' : 'pass',
    description: `Confidence ${score}%, ${abuse.totalReports.toLocaleString('en-US')} report(s) in 90 days${abuse.isWhitelisted ? '. Whitelisted by AbuseIPDB' : ''}.${cdnNote}`,
    severity: score > 50 ? 'critical' : score > 10 ? 'high' : 'low',
    source: 'AbuseIPDB',
  };
}

export function abuseIpdbDetail(abuse: AbuseIPDBResult): AnalysisDetail {
  const score = abuse.abuseConfidenceScore;
  return {
    title: `AbuseIPDB, ${abuse.ipAddress}`,
    data: {
      confidence: `${score}%`,
      reports: abuse.totalReports,
      'last reported': abuse.lastReportedAt?.slice(0, 10) || 'never',
      'usage type': abuse.usageType || 'unknown',
      isp: abuse.isp || 'unknown',
      country: abuse.countryCode || 'unknown',
    },
    status: score > 50 ? 'fail' : score > 10 ? 'warning' : 'pass',
  };
}

/** Domains: more than 5 vendors fails. IPs: 2 or more fails, 1 is a warning. */
export function virusTotalIndicator(vt: VirusTotalResult, kind: 'ip' | 'domain'): Indicator {
  const hits = vt.positives;
  const fail = kind === 'ip' ? hits >= 2 : hits > 5;
  const warn = !fail && hits > 0;
  const severity =
    kind === 'ip'
      ? hits >= 5 ? 'critical' : hits >= 2 ? 'high' : hits === 1 ? 'medium' : 'low'
      : hits > 5 ? 'critical' : hits > 0 ? 'high' : 'low';
  return {
    id: 'virustotal',
    name: 'VirusTotal',
    status: fail ? 'fail' : warn ? 'warning' : 'pass',
    description:
      hits === 0
        ? `No detections from ${vt.total} security vendors.`
        : `${hits} of ${vt.total} security vendors flag this ${kind === 'ip' ? 'IP' : 'domain'}.`,
    severity,
    source: 'VirusTotal',
  };
}

export function virusTotalDetail(vt: VirusTotalResult, kind: 'ip' | 'domain'): AnalysisDetail {
  return {
    title: 'VirusTotal',
    data:
      kind === 'ip'
        ? {
            detections: `${vt.positives} / ${vt.total}`,
            reputation: vt.reputation ?? 'n/a',
            'AS owner': vt.asOwner || 'unknown',
            country: vt.country || 'unknown',
          }
        : {
            detections: `${vt.positives} / ${vt.total}`,
            categories: vt.categories.join(', ') || 'none',
            reputation: vt.reputation ?? 'n/a',
          },
    status: vt.isClean ? 'pass' : vt.positives > 5 ? 'fail' : 'warning',
  };
}
