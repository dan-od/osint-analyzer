// Plain-words description of the scoring code, for the results side panel
// and the docs. Built from the same constants the scorer uses.
import { FAIL_MULTIPLIER, SEVERITY_POINTS } from './scoring-rules';

export const SCORE_EXPLANATION = [
  `Each failed or warning finding adds points by how serious it is (low ${SEVERITY_POINTS.low}, medium ${SEVERITY_POINTS.medium}, high ${SEVERITY_POINTS.high}, critical ${SEVERITY_POINTS.critical}); a Fail counts ${FAIL_MULTIPLIER} times as much as a Warn. The total is capped at 100.`,
  'All the blocklists are folded into one finding first, weighted by how much each list can be trusted, so one Spamhaus or URLhaus listing outweighs several hits on aggressive lists. Skipped sources do not count against the target.',
  'Confidence is the share of findings that came from a source that actually answered, so it drops when sources are skipped.',
];
