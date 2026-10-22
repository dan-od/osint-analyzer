// How long the server keeps each kind of data. The code that stores and prunes
// it and the privacy policy both read these, so the policy can't drift.
export const RETENTION = {
  /** Targets on the dashboard's "recent checks" list (no results) */
  recentChecksDays: 7,
  /** Bulk jobs with their targets and per-target results, for the CSV export */
  bulkJobDays: 7,
  /** Bulk results reused by "Reuse results from the last 24 hours" */
  resultCacheHours: 24,
  /** A sign-in lasts this long unless you log out */
  sessionDays: 30,
  /** Per-day API usage counters behind the quota display */
  usageCounterDays: 35,
  /** Email confirmation links (single use) */
  verificationLinkHours: 24,
  /** Password signups never confirmed are removed after this */
  unverifiedAccountDays: 7,
  /** In-memory rate-limit counters keyed by IP address (never written to disk) */
  rateLimitHours: 1,
} as const;

export const DAY_MS = 24 * 60 * 60 * 1000;
