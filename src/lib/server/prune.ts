// Deletes data past its retention period (lib/retention.ts) across all
// accounts: at startup and then hourly, so nothing outlives what the privacy
// policy says even when its owner never comes back.
import type Database from 'better-sqlite3';
import { DAY_MS, RETENTION } from '@/lib/retention';

const HOUR_MS = 60 * 60 * 1000;

export function pruneExpired(db: Database.Database): void {
  const now = Date.now();
  db.transaction(() => {
    db.prepare('DELETE FROM recent_checks WHERE checked_at < ?').run(now - RETENTION.recentChecksDays * DAY_MS);
    db.prepare('DELETE FROM bulk_jobs WHERE created_at < ?').run(now - RETENTION.bulkJobDays * DAY_MS);
    db.prepare('DELETE FROM lookup_cache WHERE created_at <= ?').run(now - RETENTION.resultCacheHours * HOUR_MS);
    db.prepare('DELETE FROM sessions WHERE expires < ?').run(now);
    const oldestDay = new Date(now - RETENTION.usageCounterDays * DAY_MS).toISOString().slice(0, 10);
    db.prepare('DELETE FROM api_usage WHERE day < ?').run(oldestDay);
    // Kept a week past expiry so a late click still gets "expired" or "already used"
    db.prepare('DELETE FROM verification_tokens WHERE expires < ?').run(now - 7 * DAY_MS);
    // Password signups whose email was never confirmed (they can't log in or hold data)
    const cutoff = new Date(now - RETENTION.unverifiedAccountDays * DAY_MS).toISOString();
    db.prepare(
      `DELETE FROM users WHERE email_verified IS NULL AND password_hash IS NOT NULL AND created_at < ?
       AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.user_id = users.id)`
    ).run(cutoff);
  })();
}

export function schedulePruning(db: Database.Database): void {
  try {
    pruneExpired(db);
  } catch (error) {
    console.warn('Pruning expired data failed:', (error as Error).message);
  }
  setInterval(() => {
    try {
      pruneExpired(db);
    } catch (error) {
      console.warn('Pruning expired data failed:', (error as Error).message);
    }
  }, HOUR_MS).unref();
}
