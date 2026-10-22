// Numbers quoted on the bulk page and in the docs, derived from the code
import { BULK_MAX_TARGETS, NEW_ACCOUNT_BULK_TARGETS } from './bulk-input';
import { getService } from './services';

/** Workers per job (lib/server/bulk/worker.ts) */
export const BULK_WORKERS = 3;
export { BULK_MAX_TARGETS, NEW_ACCOUNT_BULK_TARGETS };

/**
 * Average seconds for one target with free sources only, measured on a
 * mixed list of 30 IPs and 10 domains: 40 targets in 8 s with 3 workers (Oct 2026). Used for the time estimate.
 */
export const FREE_SECONDS_PER_TARGET = 0.6;

const vtPerMinute = getService('virustotal')!.perMinute!;

/** Minutes for `n` targets when VirusTotal (the slowest keyed source) is on */
export function minutesWithVirusTotal(n: number): number {
  return Math.ceil(n / vtPerMinute);
}

/** Minutes for `n` targets with free sources only */
export function minutesFreeOnly(n: number): number {
  return Math.max(1, Math.round((n * FREE_SECONDS_PER_TARGET) / BULK_WORKERS / 60));
}

export const VT_PER_MINUTE = vtPerMinute;

/**
 * Typical wall time of one full single check, measured across all five
 * target types with the feeds cached (Oct 2026): 0.3 s to 2 s, and about
 * 2.4 s for the first check after a restart while feeds download.
 */
export const TYPICAL_CHECK_SECONDS = { min: 0.3, max: 2.5 };
/** Per-source timeout before a slow source is marked "Timed out" */
export const SOURCE_TIMEOUT_SECONDS = 15;
/** DNS blocklists answer within this or count as no answer */
export const DNSBL_TIMEOUT_SECONDS = 2;

/** Logged-out visitors share the server's keys, so single checks are capped per visitor */
export const ANONYMOUS_CHECKS_PER_HOUR = 20;

/** Signups are open to anyone, but capped per visitor address so accounts can't be farmed */
export const SIGNUPS_PER_HOUR = 5;

/** Wrong passwords allowed on one confirmation link before it locks */
export const VERIFY_MAX_ATTEMPTS = 5;

/** New confirmation links per address per hour */
export const RESENDS_PER_HOUR = 3;
/** New confirmation links per visitor address per hour, across all addresses */
export const RESENDS_PER_HOUR_PER_IP = 10;
