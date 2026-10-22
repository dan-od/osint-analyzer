// Per-user 24 h result cache. Per user because results depend on which API
// keys the user has; free-sources-only results are kept apart so they never
// stand in for a full check.
import { RETENTION } from '@/lib/retention';
import { getDb } from '../db';
import type { AnalysisResult } from '@/types';
import type { BulkTarget } from '@/types/bulk';

const TTL_MS = RETENTION.resultCacheHours * 60 * 60 * 1000;

const cacheKey = (t: BulkTarget, freeOnly: boolean) => `${t.type}:${t.target}${freeOnly ? ':free' : ''}`;

export function getCachedResult(userId: number, target: BulkTarget, freeOnly = false): AnalysisResult | null {
  const row = getDb()
    .prepare('SELECT result_json FROM lookup_cache WHERE user_id = ? AND target = ? AND created_at > ?')
    .get(userId, cacheKey(target, freeOnly), Date.now() - TTL_MS) as { result_json: string } | undefined;
  return row ? (JSON.parse(row.result_json) as AnalysisResult) : null;
}

export function putCachedResult(userId: number, target: BulkTarget, result: AnalysisResult, freeOnly = false): void {
  getDb()
    .prepare(
      `INSERT INTO lookup_cache (user_id, target, result_json, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id, target) DO UPDATE SET result_json = excluded.result_json, created_at = excluded.created_at`
    )
    .run(userId, cacheKey(target, freeOnly), JSON.stringify(result), Date.now());
}

export function pruneCache(): void {
  getDb().prepare('DELETE FROM lookup_cache WHERE created_at <= ?').run(Date.now() - TTL_MS);
}
