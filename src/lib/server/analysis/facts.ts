import type { AnalysisResult, AnalysisType, Indicator, PivotLink, ResultFacts, RiskLevel } from '@/types';

const VERDICTS: Record<RiskLevel, string> = {
  low: 'No known threats',
  medium: 'Suspicious',
  high: 'Likely malicious',
  critical: 'Malicious',
};

export function verdictFor(level: RiskLevel): string {
  return VERDICTS[level];
}

/**
 * "Open in" links. Emails pivot on their domain; a domain's AbuseIPDB link
 * uses the address it resolves to when we know it.
 */
export function pivotsFor(kind: AnalysisType, target: string, hostIp?: string | null): PivotLink[] {
  const enc = encodeURIComponent;
  if (kind === 'ip') {
    return [
      { label: 'VirusTotal', target, url: `https://www.virustotal.com/gui/ip-address/${enc(target)}` },
      { label: 'AbuseIPDB', target, url: `https://www.abuseipdb.com/check/${enc(target)}` },
      // IPVoid has no per-IP URL (its checker is a POST form), so this opens the form
      { label: 'IPVoid', target, url: 'https://www.ipvoid.com/ip-blacklist-check/' },
    ];
  }
  const domain = kind === 'email' ? target.split('@')[1] : kind === 'domain' ? target : null;
  if (!domain) return [];
  const links: PivotLink[] = [
    { label: 'VirusTotal', target: domain, url: `https://www.virustotal.com/gui/domain/${enc(domain)}` },
    { label: 'URLVoid', target: domain, url: `https://www.urlvoid.com/scan/${enc(domain)}/` },
  ];
  if (kind === 'domain') {
    const abuseTarget = hostIp || domain;
    links.push({ label: 'AbuseIPDB', target: abuseTarget, url: `https://www.abuseipdb.com/check/${enc(abuseTarget)}` });
  }
  return links;
}

const SEVERITY_RANK: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const STATUS_RANK: Record<Indicator['status'], number> = { fail: 0, warning: 1, pass: 2, unknown: 3 };

/** Flagged first (fail, then warn), most severe first; then passes, then skipped. */
export function sortFindings(indicators: Indicator[]): Indicator[] {
  return [...indicators].sort(
    (a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  );
}

/** The most serious finding in a few words, for tables and the CSV */
function topFinding(result: AnalysisResult): string | null {
  const top = sortFindings(result.indicators)[0];
  if (!top || (top.status !== 'fail' && top.status !== 'warning')) return null;
  if (top.id === 'blocklist-coverage' && result.blocklist) {
    const listed = result.blocklist.sources.filter((s) => s.status === 'listed').map((s) => s.name);
    const named = listed.slice(0, 2).join(' and ');
    return `On ${listed.length} blocklist${listed.length === 1 ? '' : 's'}${named ? `, incl. ${named}` : ''}`;
  }
  // First sentence only, kept short
  const sentence = top.description.split(/(?<=\.)\s/)[0].replace(/\.$/, '');
  const text = `${top.name}: ${sentence}`;
  return text.length > 90 ? `${text.slice(0, 87).trimEnd()}…` : text;
}

export function withFacts(
  result: AnalysisResult,
  facts: Omit<ResultFacts, 'verdict' | 'blocklistHits' | 'topFinding'>
): AnalysisResult {
  const blocklistHits = result.blocklist ? `${result.blocklist.flagged}/${result.blocklist.checked}` : null;
  return {
    ...result,
    facts: { verdict: verdictFor(result.riskLevel), blocklistHits, topFinding: topFinding(result), ...facts },
  };
}
