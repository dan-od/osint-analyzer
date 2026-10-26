// The popularity ranking behind look-alike detection: a custom Tranco list
// built from Tranco's default sources minus Cloudflare Radar, whose ranking
// data is CC BY-NC 4.0 (non-commercial). Tranco states no licence of its own.
// https://tranco-list.eu/api_documentation

/** Tranco's default providers without "radar" */
export const TRANCO_PROVIDERS = ['crux', 'farsight', 'majestic', 'umbrella'];
/** Days of source data each generated list averages (Tranco's default) */
export const TRANCO_WINDOW_DAYS = 30;
/** Rows kept: the top 100k is the "genuine article" set */
export const TRANCO_ROWS = 100_000;
/** A list whose data ends more than this many days ago is not used: look-alike checks are skipped */
export const TRANCO_MAX_AGE_DAYS = 7;

/**
 * Permanent ID of the list bundled in assets/tranco/, so a new container works
 * before its first download: https://tranco-list.eu/list/<ID>. Written by
 * `npm run tranco:snapshot`; null until a list has been bundled.
 */
export const BUNDLED_TRANCO_LIST_ID: string | null = null;

export interface TrancoListMeta {
  listId: string;
  /** First and last day of source data, YYYY-MM-DD */
  startDate: string;
  endDate: string;
  providers: string[];
  rows: number;
  /** When Tranco generated it (ISO) */
  createdOn: string | null;
}

/** The configuration sent to Tranco's PUT /api/lists/create for a window ending on `endDate` */
export function trancoConfiguration(endDate: string) {
  const start = new Date(`${endDate}T00:00:00Z`);
  start.setUTCDate(start.getUTCDate() - (TRANCO_WINDOW_DAYS - 1));
  return {
    providers: TRANCO_PROVIDERS,
    startDate: start.toISOString().slice(0, 10),
    endDate,
    combinationMethod: 'dowdall',
    listPrefix: 'full',
    filterPLD: 'on',
  };
}

/** Why a list's configuration can't be used, or null when it can */
export function configurationProblem(config: { providers?: unknown; filterPLD?: unknown } | null | undefined): string | null {
  if (!config || !Array.isArray(config.providers)) return 'its configuration is missing';
  if (config.providers.includes('radar')) return 'it includes Cloudflare Radar data (CC BY-NC)';
  if (config.filterPLD !== 'on') return 'it ranks subdomains, not registrable domains';
  return null;
}

/** Whole days since the list's last day of data */
export function listAgeDays(meta: Pick<TrancoListMeta, 'endDate'>, now: number): number {
  return Math.max(0, Math.floor((now - Date.parse(`${meta.endDate}T23:59:59Z`)) / 86_400_000) + 1);
}
