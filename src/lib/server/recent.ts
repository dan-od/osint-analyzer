// What a logged-in user checked recently: the target and its type, nothing
// else. Kept for 7 days so the dashboard can list it.
import { getDb } from './db';
import { DAY_MS, RETENTION } from '@/lib/retention';
import { countLookup } from './auth/users';
import type { AnalysisType } from '@/types';

const KEEP_MS = RETENTION.recentChecksDays * DAY_MS;

export interface RecentCheck {
  target: string;
  type: AnalysisType;
  checkedAt: string;
}

export function recordCheck(userId: number, target: string, type: AnalysisType): void {
  countLookup(userId);
  const db = getDb();
  const now = Date.now();
  db.prepare('DELETE FROM recent_checks WHERE checked_at < ?').run(now - KEEP_MS);
  db.prepare(
    `INSERT INTO recent_checks (user_id, target, type, checked_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, target) DO UPDATE SET checked_at = excluded.checked_at, type = excluded.type`
  ).run(userId, target, type, now);
}

export function listRecentChecks(userId: number, limit = 12): RecentCheck[] {
  const rows = getDb()
    .prepare('SELECT target, type, checked_at FROM recent_checks WHERE user_id = ? AND checked_at >= ? ORDER BY checked_at DESC LIMIT ?')
    .all(userId, Date.now() - KEEP_MS, limit) as { target: string; type: AnalysisType; checked_at: number }[];
  return rows.map((r) => ({ target: r.target, type: r.type, checkedAt: new Date(r.checked_at).toISOString() }));
}
