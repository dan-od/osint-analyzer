// Turns individual blocklist answers into the "Flagged by 4/27 sources" summary.
// Listings are weighted by how much each source can be trusted: one hit on
// Spamhaus or URLhaus outweighs several hits on aggressive lists like UCEPROTECT L3.
import type { AnalysisDetail, BlocklistCoverage, BlocklistSourceResult, BlocklistTrust, Indicator } from '@/types';
import type { ServiceId } from '@/lib/services';
import type { AnalysisContext } from '../analysis/context';
import { COVERAGE_THRESHOLDS, TRUST_WEIGHT } from '@/lib/scoring-rules';


const TRUST_ORDER: BlocklistTrust[] = ['high', 'medium', 'low', 'noisy'];

export function summarizeCoverage(sources: BlocklistSourceResult[]): BlocklistCoverage {
  const listed = sources.filter((s) => s.status === 'listed');
  const checked = sources.filter((s) => s.status === 'listed' || s.status === 'clean').length;
  // Noisy-OR: 1 − Π(1 − weight) over the sources that list the target
  const clearProbability = listed.reduce((p, s) => p * (1 - TRUST_WEIGHT[s.trust]), 1);
  const sorted = [...sources].sort(
    (a, b) =>
      Number(b.status === 'listed') - Number(a.status === 'listed') ||
      TRUST_ORDER.indexOf(a.trust) - TRUST_ORDER.indexOf(b.trust)
  );
  return {
    flagged: listed.length,
    checked,
    total: sources.length,
    weightedScore: Math.round((1 - clearProbability) * 100),
    sources: sorted,
  };
}

export function coverageIndicator(coverage: BlocklistCoverage): Indicator {
  const { flagged, checked, weightedScore } = coverage;
  const listedNames = coverage.sources.filter((s) => s.status === 'listed').map((s) => s.name);
  const refused = coverage.sources.filter((s) => s.status === 'refused').length;
  const unavailable = coverage.total - checked - refused;
  const notes = [
    refused ? `${refused} refused the query` : '',
    unavailable ? `${unavailable} unavailable/not checked` : '',
  ].filter(Boolean);

  const base = { id: 'blocklist-coverage', name: 'Blocklist coverage', source: 'Blocklists' };
  if (checked === 0) {
    return { ...base, status: 'unknown', severity: 'low', description: 'No blocklist could be checked' };
  }
  const description =
    `Flagged by ${flagged}/${checked} sources` +
    (listedNames.length ? `: ${listedNames.slice(0, 6).join(', ')}${listedNames.length > 6 ? '…' : ''}` : '') +
    ` (weighted score ${weightedScore}/100)` +
    (notes.length ? ` – ${notes.join(', ')}` : '');

  const band = COVERAGE_THRESHOLDS.find((t) => weightedScore >= t.min);
  if (band) return { ...base, status: band.status, severity: band.severity, description };
  return { ...base, status: 'pass', severity: 'low', description };
}

/** Compact version for the generic details grid */
export function coverageDetail(coverage: BlocklistCoverage): AnalysisDetail {
  const by = (status: BlocklistSourceResult['status']) =>
    coverage.sources.filter((s) => s.status === status).map((s) => s.name);
  return {
    title: 'Blocklist Coverage',
    data: {
      flaggedBy: `${coverage.flagged}/${coverage.checked} sources`,
      weightedScore: `${coverage.weightedScore}/100`,
      listedOn: by('listed').join(', ') || 'None',
      refused: by('refused').join(', ') || 'None',
      notChecked: [...by('error'), ...by('skipped')].join(', ') || 'None',
    },
    status: coverage.weightedScore >= 35 ? 'fail' : coverage.flagged > 0 ? 'warning' : 'pass',
  };
}

/** Runs a keyed API source, reporting it as "skipped" when no key is available. */
export async function keyedSource(
  ctx: AnalysisContext,
  service: ServiceId,
  meta: Pick<BlocklistSourceResult, 'id' | 'name' | 'trust'>,
  call: (key: string) => Promise<Pick<BlocklistSourceResult, 'status' | 'detail'>>
): Promise<BlocklistSourceResult> {
  const base = { ...meta, kind: 'api' as const };
  const grant = await ctx.keys.acquire(service);
  if (!grant.ok) return { ...base, status: 'skipped', detail: grant.reason };
  return { ...base, ...(await call(grant.key)) };
}
