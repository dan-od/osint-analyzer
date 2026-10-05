// Per-user API call counters (UTC days), used to show and enforce free-tier quotas
import { getDb } from '../db';
import type { ServiceId, ServiceQuota } from '@/lib/services';

export type KeySource = 'user' | 'server';

function utcDay(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export function recordUsage(userId: number, service: ServiceId, source: KeySource, count = 1): void {
  getDb()
    .prepare(
      `INSERT INTO api_usage (user_id, service, key_source, day, count) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id, service, key_source, day) DO UPDATE SET count = count + excluded.count`
    )
    .run(userId, service, source, utcDay(), count);
}

/** Calls made in the current quota period (today, or this calendar month). */
export function usedInPeriod(
  userId: number,
  service: ServiceId,
  source: KeySource,
  period: ServiceQuota['period']
): number {
  const today = utcDay();
  const from =
    period === 'day'
      ? today
      : period === 'week'
        ? utcDay(new Date(Date.now() - 6 * 24 * 60 * 60 * 1000))
        : `${today.slice(0, 7)}-01`;
  const row = getDb()
    .prepare(
      `SELECT COALESCE(SUM(count), 0) AS n FROM api_usage
       WHERE user_id = ? AND service = ? AND key_source = ? AND day >= ? AND day <= ?`
    )
    .get(userId, service, source, from, today);
  return (row as { n: number } | undefined)?.n ?? 0;
}

export function usedToday(userId: number, service: ServiceId, source: KeySource): number {
  return usedInPeriod(userId, service, source, 'day');
}
