// Findings from look-alike detection (src/lib/lookalike/detect.ts):
// - embedding, confusable, brand + credential word: Fail, critical
// - one letter off a top-1k brand: Warn, high
// - brand name on another suffix: Warn, medium (low on a country-code TLD)
// - brand plus another word: Warn, low
// - a label mixing scripts: Warn, medium, on its own row
// A popular domain itself gets a Pass row. Type-only imports outside this
// folder, so the tests can load it directly.
import type { AnalysisDetail, Indicator, RiskLevel } from '@/types';
import type { LookalikeKind, LookalikeMatch, LookalikeReport } from '../../lookalike/detect';
import { LIMITS } from '../../lookalike/detect';
import { scriptInfo } from '../../lookalike/skeleton';
import type { TrancoListMeta } from '../../lookalike/tranco-list';

const SOURCE = 'Look-alike rules';

const GRADE: Record<LookalikeKind, { status: 'fail' | 'warning'; severity: RiskLevel; name: string }> = {
  embedding: { status: 'fail', severity: 'critical', name: 'Brand in the address' },
  confusable: { status: 'fail', severity: 'critical', name: 'Look-alike characters' },
  'credential-combo': { status: 'fail', severity: 'critical', name: 'Brand with a login word' },
  'edit-distance': { status: 'warning', severity: 'high', name: 'One letter off a brand' },
  'tld-swap': { status: 'warning', severity: 'medium', name: 'Brand name, other suffix' },
  'brand-word': { status: 'warning', severity: 'low', name: 'Brand with other words' },
};

const n = (x: number) => x.toLocaleString('en-US');
const rankOf = (m: LookalikeMatch) => `rank ${n(m.targetRank)}`;

/** "аpple.com (xn--pple-43d.com)" when the host has IDN labels, else the host */
function shown(report: LookalikeReport): string {
  return report.unicode !== report.ascii ? `${report.unicode} (${report.ascii})` : report.ascii;
}

function oddCharacters(report: LookalikeReport, label: string): string {
  const mixed = report.mixedScript.find((m) => m.label === label);
  if (mixed) return mixed.info.odd.map((c) => `${c.script} "${c.char}" (${c.codePoint})`).join(', ');
  const info = scriptInfo(label);
  return info.wholeScript ? `written entirely in ${info.wholeScript}` : '';
}

function matchFinding(report: LookalikeReport, match: LookalikeMatch, others: LookalikeMatch[]): Indicator {
  const grade = GRADE[match.kind];
  const severity = match.kind === 'tld-swap' && match.countryCode ? 'low' : grade.severity;
  let text = `Imitates ${match.target} (${rankOf(match)}): ${match.why}.`;
  if (match.kind === 'confusable' && report.unicode !== report.ascii) {
    const odd = oddCharacters(report, report.label ?? '');
    text = `Imitates ${match.target} (${rankOf(match)}): ${shown(report)} renders like ${match.target}${odd ? `; ${odd}` : ''}.`;
  } else if (report.unicode !== report.ascii) {
    text += ` Decoded: ${report.unicode}.`;
  }
  if (match.kind === 'tld-swap' && match.countryCode) text += ' Brands often own their name on country domains, so this alone is weak.';
  if (report.platform) text += ` It is a site on ${report.platform}, where anyone can publish.`;
  const extra = others.filter((o) => o !== match).map((o) => GRADE[o.kind].name.toLowerCase());
  if (extra.length) text += ` Also: ${Array.from(new Set(extra)).join(', ')}.`;
  return { id: 'lookalike', name: grade.name, status: grade.status, severity, description: text, source: SOURCE };
}

export function lookalikeFindings(report: LookalikeReport, list: TrancoListMeta): Indicator[] {
  const findings: Indicator[] = [];
  if (report.rank !== null) {
    findings.push({
      id: 'lookalike',
      name: 'Look-alike check',
      status: 'pass',
      severity: 'low',
      description: `A popular domain in its own right (Tranco rank ${n(report.rank)}), not an imitation.`,
      source: SOURCE,
    });
    return findings;
  }

  const [strongest] = report.matches;
  if (strongest) {
    findings.push(matchFinding(report, strongest, report.matches));
  } else if (report.registrable) {
    const where = report.platform ? `A site on ${report.platform}; its name doesn't` : "Doesn't";
    findings.push({
      id: 'lookalike',
      name: 'Look-alike check',
      status: 'pass',
      severity: 'low',
      description: `${where} imitate any of the ${n(LIMITS.brands)} most popular domains (Tranco ${list.listId}).${report.scriptExempt ? ` ${report.scriptExempt}, which is allowed.` : ''}`,
      source: SOURCE,
    });
  }

  for (const { label, info } of report.mixedScript) {
    const ascii = report.ascii.split('.').find((l) => l.startsWith('xn--') && report.unicode.includes(label));
    findings.push({
      id: 'mixed-script',
      name: 'Mixed scripts',
      status: 'warning',
      severity: 'medium',
      description: `"${label}"${ascii ? ` (${ascii})` : ''} mixes ${info.scripts.join(' and ')}: ${info.odd.map((c) => `${c.script} "${c.char}" (${c.codePoint})`).join(', ')}. Real sites rarely do this; look-alikes do.`,
      source: SOURCE,
    });
  }
  return findings;
}

/** The raw-data panel: what was compared, against which list */
export function lookalikeDetail(report: LookalikeReport, list: TrancoListMeta, ageDays: number): AnalysisDetail {
  const flagged = report.matches[0] ? GRADE[report.matches[0].kind].status : report.mixedScript.length ? 'warning' : 'pass';
  return {
    title: `Look-alike check, ${report.unicode}`,
    data: {
      ...(report.unicode !== report.ascii ? { decoded: report.unicode, punycode: report.ascii } : {}),
      'registrable domain': report.registrable ?? 'none',
      ...(report.platform ? { platform: report.platform } : {}),
      'tranco rank': report.rank !== null ? n(report.rank) : `not in the top ${n(LIMITS.known)}`,
      matches: report.matches.map((m) => `${m.kind} → ${m.target}`).join('; ') || 'none',
      'tranco list': `${list.listId} (data ${list.startDate} to ${list.endDate}, ${ageDays} day${ageDays === 1 ? '' : 's'} old)`,
    },
    status: flagged,
  };
}
