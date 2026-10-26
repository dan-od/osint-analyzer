import type { AnalysisType, AnalysisResult, Indicator, RiskLevel, AnalysisDetail } from '@/types';
import { FAIL_MULTIPLIER, SCORE_CAP, PATTERN_ONLY_NOTE, SEVERITY_POINTS, UNCORROBORATED_CAP, riskLevelFor } from '@/lib/scoring-rules';

export { PATTERN_ONLY_NOTE };
import type { AnalysisContext } from './context';
import { sortFindings } from './facts';

const NUMBER_WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine'];
const count = (n: number) => NUMBER_WORDS[n] ?? String(n);

function listNames(indicators: Indicator[]): string {
  // "Abuse reports" → "abuse reports", but "VirusTotal" and "DMARC record" keep their case
  const soften = (name: string) => (/^[A-Z][a-z]+(\s|$)/.test(name) ? name[0].toLowerCase() + name.slice(1) : name);
  const names = indicators.slice(0, 3).map((i) => soften(i.name));
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

export interface ScoreOptions {
  /**
   * Findings from an independent source (blocklist, abuse reports, VirusTotal,
   * phishing feed). When given, a result whose Fails and Warns all come from
   * elsewhere (pattern rules) is capped at Medium.
   */
  independent?: (indicator: Indicator) => boolean;
}

const flagged = (i: Indicator) => i.status === 'fail' || i.status === 'warning';

/** The score, capped at Medium when only pattern rules flagged anything and options.independent is set */
export function scoreFindings(indicators: Indicator[], options: ScoreOptions = {}): { score: number; patternOnly: boolean; capped: boolean } {
  const raw = calculateRiskScore(indicators);
  const hits = indicators.filter(flagged);
  const patternOnly = !!options.independent && hits.length > 0 && !hits.some(options.independent);
  const score = patternOnly ? Math.min(raw, UNCORROBORATED_CAP) : raw;
  return { score, patternOnly, capped: score < raw };
}

/** One or two sentences, in plain words, for the verdict band. */
function summarize(level: RiskLevel, indicators: Indicator[], answered: number, patternOnly = false): string {
  const note = patternOnly && level !== 'low' ? ` ${PATTERN_ONLY_NOTE}` : '';
  const sorted = sortFindings(indicators);
  const fails = sorted.filter((i) => i.status === 'fail');
  const warns = sorted.filter((i) => i.status === 'warning');
  if (level === 'critical') {
    return `${count(fails.length)} serious finding${fails.length === 1 ? '' : 's'}: ${listNames(fails)}. Treat as likely fraudulent.`;
  }
  if (level === 'high') {
    const flagged = [...fails, ...warns];
    return `${count(flagged.length)} finding${flagged.length === 1 ? '' : 's'} against it, led by ${listNames(flagged)}. Treat with suspicion and verify before acting.`;
  }
  if (level === 'medium') {
    const flagged = [...fails, ...warns];
    return `Some warning signs: ${listNames(flagged)}. Nothing conclusive, but be careful.${note}`;
  }
  if (fails.length + warns.length > 0) {
    return `Only minor notes (${listNames([...fails, ...warns])}). ${answered} source${answered === 1 ? '' : 's'} answered and none reported it as malicious.`;
  }
  return `Nothing flagged by the ${answered} source${answered === 1 ? '' : 's'} that answered. Not reported is not the same as safe.`;
}

export function buildResult(
  type: AnalysisType,
  query: string,
  indicators: Indicator[],
  details: Record<string, AnalysisDetail>,
  ctx: AnalysisContext,
  options: ScoreOptions = {}
): AnalysisResult {
  // Keyed sources that were skipped without a row of their own still show up
  const skippedSources = ctx.keys.skipped();
  for (const skipped of skippedSources) {
    if (indicators.some((i) => i.id === `skipped-${skipped.service}`)) continue;
    indicators.push({
      id: `skipped-${skipped.service}`,
      name: skipped.name,
      status: 'unknown',
      description: skipped.reason,
      severity: 'low',
      source: skipped.name,
    });
  }

  const { score: riskScore, patternOnly } = scoreFindings(indicators, options);
  const riskLevel = riskLevelFor(riskScore);

  // Confidence: the share of findings that came from a source that actually answered
  const totalChecks = indicators.length;
  const unknownChecks = indicators.filter((i) => i.status === 'unknown').length;
  const confidence = totalChecks > 0 ? Math.round(((totalChecks - unknownChecks) / totalChecks) * 100) : 0;

  const { answered, totalSources } = ctx.progress;

  return {
    type,
    query,
    timestamp: new Date().toISOString(),
    riskScore,
    riskLevel,
    confidence,
    summary: summarize(riskLevel, indicators, answered, patternOnly),
    indicators: sortFindings(indicators),
    details,
    recommendations: generateRecommendations(type, riskLevel, indicators),
    skippedSources,
    sources: { answered, total: totalSources },
    elapsedMs: ctx.progress.elapsedMs(),
  };
}

export function calculateRiskScore(indicators: Indicator[]): number {
  let score = 0;
  for (const indicator of indicators) {
    if (indicator.status === 'fail') score += SEVERITY_POINTS[indicator.severity] * FAIL_MULTIPLIER;
    else if (indicator.status === 'warning') score += SEVERITY_POINTS[indicator.severity];
  }
  return Math.min(SCORE_CAP, Math.max(0, Math.round(score)));
}

function generateRecommendations(type: AnalysisType, riskLevel: RiskLevel, indicators: Indicator[]): string[] {
  const recommendations: string[] = [];

  const typeRecs: Record<AnalysisType, string[]> = {
    email: [
      'Verify the sender through another channel before replying.',
      'Check the domain for misspellings of a brand you know.',
      'Do not open links or attachments from this sender.',
    ],
    domain: [
      'Do not enter passwords or payment details on this site.',
      'Reach the organisation through a link you already trust instead.',
      'Look for contact details and a physical address you can verify.',
    ],
    phone: [
      'Do not call back unknown numbers straight away.',
      'Look the number up on the organisation’s official website.',
      'Never share one-time codes or card details on a call you did not start.',
    ],
    ip: [
      'Block or rate-limit the address at your firewall or WAF if it is hitting your services.',
      'Correlate with your own logs (auth failures, scans) before acting.',
      'Use the Open in links to review its full history.',
    ],
    crypto: [
      'Do not send funds to this address.',
      'Confirm the address through a second, trusted channel.',
      'Use a reputable exchange with proper verification.',
    ],
  };

  if (riskLevel === 'critical') {
    recommendations.push('Avoid all interaction with it.');
  } else if (riskLevel === 'high') {
    recommendations.push('Proceed with extreme caution: several sources agree something is wrong.');
  }

  for (const indicator of indicators) {
    if (indicator.status !== 'fail') continue;
    if (indicator.id === 'lookalike') recommendations.push('It imitates a known brand. Do not trust it.');
    if (indicator.id === 'virustotal') recommendations.push('Several security vendors flag it as malicious.');
  }

  const room = 3 - recommendations.length;
  recommendations.push(...typeRecs[type].slice(0, room > 0 ? room : 1));
  recommendations.push('Report it to the relevant authority (for example the FTC, IC3 or the Canadian Anti-Fraud Centre).');

  return recommendations.slice(0, 5);
}
