// Bulk job storage
import crypto from 'crypto';
import { getDb } from '../db';
import type { AnalysisResult } from '@/types';
import {
  DEFAULT_BULK_OPTIONS,
  type BulkItemStatus,
  type BulkItemSummary,
  type BulkJobDetail,
  type BulkJobStatus,
  type BulkJobSummary,
  type BulkOptions,
  type BulkTarget,
  type BulkTargetType,
} from '@/types/bulk';

const JOB_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const ACTIVE = "('queued', 'running', 'paused')";

interface JobRow {
  id: string;
  user_id: number;
  name: string;
  status: BulkJobStatus;
  options_json: string;
  pasted: number;
  total: number;
  created_at: number;
}

interface ItemRow {
  job_id: string;
  idx: number;
  target: string;
  type: BulkTargetType;
  status: BulkItemStatus;
  cached: number;
  result_json: string | null;
  error: string | null;
  risk_level: string | null;
  risk_score: number | null;
}

export interface NewJob {
  name: string;
  options: BulkOptions;
  pasted: number;
  targets: BulkTarget[];
  /** Private/reserved IPs, stored as skipped items so they show up in the export */
  skippedInternal: BulkTarget[];
}

export function createJob(userId: number, job: NewJob): string {
  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  const insertItem = db.prepare('INSERT INTO bulk_items (job_id, idx, target, type, status) VALUES (?, ?, ?, ?, ?)');
  db.transaction(() => {
    db.prepare('DELETE FROM bulk_jobs WHERE user_id = ? AND created_at < ?').run(userId, now - JOB_RETENTION_MS);
    db.prepare(
      `INSERT INTO bulk_jobs (id, user_id, name, status, options_json, pasted, total, created_at, updated_at)
       VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?)`
    ).run(id, userId, job.name, JSON.stringify(job.options), job.pasted, job.targets.length + job.skippedInternal.length, now, now);
    let idx = 0;
    for (const t of job.targets) insertItem.run(id, idx++, t.target, t.type, 'queued');
    for (const t of job.skippedInternal) insertItem.run(id, idx++, t.target, t.type, 'skipped');
  })();
  return id;
}

export function getJobRow(jobId: string): (JobRow & { options: BulkOptions }) | null {
  const row = getDb().prepare('SELECT * FROM bulk_jobs WHERE id = ?').get(jobId) as JobRow | undefined;
  return row ? { ...row, options: parseOptions(row.options_json) } : null;
}

function parseOptions(json: string): BulkOptions {
  try {
    return { ...DEFAULT_BULK_OPTIONS, ...(JSON.parse(json) as Partial<BulkOptions>) };
  } catch {
    return DEFAULT_BULK_OPTIONS;
  }
}

export function setJobStatus(jobId: string, status: BulkJobStatus): void {
  getDb().prepare('UPDATE bulk_jobs SET status = ?, updated_at = ? WHERE id = ?').run(status, Date.now(), jobId);
}

export function cancelJob(userId: number, jobId: string): boolean {
  const db = getDb();
  return db.transaction(() => {
    const changed = db
      .prepare(`UPDATE bulk_jobs SET status = 'cancelled', updated_at = ? WHERE id = ? AND user_id = ? AND status IN ${ACTIVE}`)
      .run(Date.now(), jobId, userId).changes;
    if (changed) db.prepare("UPDATE bulk_items SET status = 'cancelled' WHERE job_id = ? AND status = 'queued'").run(jobId);
    return changed > 0;
  })();
}

/** Workers stop taking new items; ones in flight finish. */
export function pauseJob(userId: number, jobId: string): boolean {
  return (
    getDb()
      .prepare("UPDATE bulk_jobs SET status = 'paused', updated_at = ? WHERE id = ? AND user_id = ? AND status IN ('queued', 'running')")
      .run(Date.now(), jobId, userId).changes > 0
  );
}

export function resumeJob(userId: number, jobId: string): boolean {
  return (
    getDb()
      .prepare("UPDATE bulk_jobs SET status = 'queued', updated_at = ? WHERE id = ? AND user_id = ? AND status = 'paused'")
      .run(Date.now(), jobId, userId).changes > 0
  );
}

/** Atomically takes the next queued item for a worker. */
export function claimNextItem(jobId: string): ItemRow | null {
  return (
    (getDb()
      .prepare(
        `UPDATE bulk_items SET status = 'running'
         WHERE job_id = ? AND idx = (SELECT idx FROM bulk_items WHERE job_id = ? AND status = 'queued' ORDER BY idx LIMIT 1)
         RETURNING *`
      )
      .get(jobId, jobId) as ItemRow | undefined) ?? null
  );
}

/** A worker was paused mid-claim: put the item back */
export function requeueItem(jobId: string, idx: number): void {
  getDb().prepare("UPDATE bulk_items SET status = 'queued' WHERE job_id = ? AND idx = ? AND status = 'running'").run(jobId, idx);
}

export function completeItem(jobId: string, idx: number, result: AnalysisResult, cached: boolean): void {
  getDb()
    .prepare(
      `UPDATE bulk_items SET status = 'done', result_json = ?, cached = ?, error = NULL, risk_level = ?, risk_score = ?
       WHERE job_id = ? AND idx = ?`
    )
    .run(JSON.stringify(result), cached ? 1 : 0, result.riskLevel, result.riskScore, jobId, idx);
}

export function failItem(jobId: string, idx: number, error: string): void {
  getDb().prepare("UPDATE bulk_items SET status = 'error', error = ? WHERE job_id = ? AND idx = ?").run(error, jobId, idx);
}

/** After a restart: put interrupted items back in the queue and list jobs to resume. */
export function jobsToResume(): string[] {
  const db = getDb();
  const ids = (db.prepare("SELECT id FROM bulk_jobs WHERE status IN ('queued', 'running')").all() as { id: string }[]).map(
    (r) => r.id
  );
  const requeue = db.prepare("UPDATE bulk_items SET status = 'queued' WHERE job_id = ? AND status = 'running'");
  ids.forEach((id) => requeue.run(id));
  return ids;
}

export function hasActiveJob(userId: number): boolean {
  return !!getDb().prepare(`SELECT 1 FROM bulk_jobs WHERE user_id = ? AND status IN ${ACTIVE}`).get(userId);
}

function summarizeJob(row: JobRow): BulkJobSummary {
  const c = getDb()
    .prepare(
      `SELECT
         SUM(status IN ('done', 'error', 'skipped')) AS completed,
         SUM(status = 'error') AS failed,
         SUM(status = 'done' AND risk_level IS NOT NULL AND risk_level != 'low') AS flagged,
         SUM(status = 'done' AND (risk_level IS NULL OR risk_level = 'low')) AS clean,
         SUM(status IN ('queued', 'running')) AS pending,
         SUM(status = 'skipped') AS skipped
       FROM bulk_items WHERE job_id = ?`
    )
    .get(row.id) as Record<string, number | null>;
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    options: parseOptions(row.options_json),
    pasted: row.pasted,
    total: row.total,
    completed: c.completed ?? 0,
    failed: c.failed ?? 0,
    flagged: c.flagged ?? 0,
    clean: c.clean ?? 0,
    pending: c.pending ?? 0,
    skipped: c.skipped ?? 0,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

export function listJobs(userId: number, limit = 10): BulkJobSummary[] {
  const rows = getDb()
    .prepare('SELECT * FROM bulk_jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?')
    .all(userId, limit) as JobRow[];
  return rows.map(summarizeJob);
}

function summarizeItem(row: ItemRow): BulkItemSummary {
  const result = row.result_json ? (JSON.parse(row.result_json) as AnalysisResult) : null;
  return {
    idx: row.idx,
    target: row.target,
    type: row.type,
    status: row.status,
    cached: !!row.cached,
    error: row.error,
    riskScore: result?.riskScore ?? null,
    riskLevel: result?.riskLevel ?? null,
    facts: result?.facts ?? null,
  };
}

export function getJobDetail(userId: number, jobId: string): BulkJobDetail | null {
  const row = getDb().prepare('SELECT * FROM bulk_jobs WHERE id = ? AND user_id = ?').get(jobId, userId) as
    | JobRow
    | undefined;
  if (!row) return null;
  const items = getDb().prepare('SELECT * FROM bulk_items WHERE job_id = ? ORDER BY idx').all(jobId) as ItemRow[];
  return { ...summarizeJob(row), items: items.map(summarizeItem) };
}

export function getItemResult(userId: number, jobId: string, idx: number): AnalysisResult | null {
  const row = getDb()
    .prepare(
      `SELECT i.result_json FROM bulk_items i JOIN bulk_jobs j ON j.id = i.job_id
       WHERE i.job_id = ? AND i.idx = ? AND j.user_id = ?`
    )
    .get(jobId, idx, userId) as { result_json: string | null } | undefined;
  return row?.result_json ? (JSON.parse(row.result_json) as AnalysisResult) : null;
}
