// The numbers behind the risk score. Used by the scoring code and quoted by
// the docs and the "How this score works" panel, so the explanation can't
// drift from the implementation.
import type { BlocklistTrust, RiskLevel } from '@/types';

/** Points a Warn finding adds, by severity. A Fail adds FAIL_MULTIPLIER times as much. */
export const SEVERITY_POINTS: Record<RiskLevel, number> = { low: 5, medium: 15, high: 25, critical: 40 };
export const FAIL_MULTIPLIER = 1.5;
export const SCORE_CAP = 100;

/** Score bands, inclusive */
export const RISK_BANDS: { level: RiskLevel; min: number; max: number }[] = [
  { level: 'low', min: 0, max: 25 },
  { level: 'medium', min: 26, max: 50 },
  { level: 'high', min: 51, max: 75 },
  { level: 'critical', min: 76, max: 100 },
];

export function riskLevelFor(score: number): RiskLevel {
  return RISK_BANDS.find((b) => score <= b.max)?.level ?? 'critical';
}

/**
 * Blocklists are combined before scoring: each listing counts with its
 * source's trust weight, combined as 1 − Π(1 − weight), giving 0–100.
 */
export const TRUST_WEIGHT: Record<BlocklistTrust, number> = {
  high: 0.6,
  medium: 0.3,
  low: 0.15,
  noisy: 0.05,
};

/** How the combined blocklist score becomes one finding */
export const COVERAGE_THRESHOLDS: { min: number; status: 'fail' | 'warning'; severity: RiskLevel }[] = [
  { min: 60, status: 'fail', severity: 'critical' },
  { min: 35, status: 'fail', severity: 'high' },
  { min: 15, status: 'warning', severity: 'medium' },
  { min: 1, status: 'warning', severity: 'low' },
];
