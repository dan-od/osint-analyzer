// In-process bulk queue. Each job runs a few workers that pull items one at a
// time; per-service rate limits (e.g. VirusTotal 4/min) make them wait inside
// the key resolver, and daily quotas make sources skip. Bulk lookups only use
// the job owner's own keys. Unfinished jobs resume after a server restart.
import { countLookup, findUserById } from '../auth/users';
import { analyzeTarget, createAnalysisContext } from '../analysis';
import { preloadFeeds } from '../blocklists/feeds';
import { preloadBrandIndex } from '../lookalike';
import { getCachedResult, pruneCache, putCachedResult } from './cache';
import { claimNextItem, completeItem, failItem, getJobRow, jobsToResume, requeueItem, setJobStatus } from './jobs';

import { BULK_WORKERS } from '@/lib/bulk-limits';

const WORKERS_PER_JOB = BULK_WORKERS;

const globalForBulk = globalThis as unknown as { __osintBulk?: { running: Set<string>; resumed: boolean } };
const state = (globalForBulk.__osintBulk ??= { running: new Set(), resumed: false });

export function startJob(jobId: string): void {
  if (state.running.has(jobId)) return;
  state.running.add(jobId);
  runJob(jobId)
    .catch((error) => console.error(`Bulk job ${jobId} crashed:`, error))
    .finally(() => state.running.delete(jobId));
}

/** Called from the bulk API routes so interrupted jobs continue after a restart. */
export function resumeBulkJobs(): void {
  if (state.resumed) return;
  state.resumed = true;
  jobsToResume().forEach(startJob);
}

async function runJob(jobId: string): Promise<void> {
  const job = getJobRow(jobId);
  if (!job || job.status === 'done' || job.status === 'cancelled' || job.status === 'paused') return;
  const user = findUserById(job.user_id);
  if (!user) return;
  const { options } = job;

  setJobStatus(jobId, 'running');
  pruneCache();
  await preloadFeeds();
  preloadBrandIndex();

  const stopped = () => {
    const status = getJobRow(jobId)?.status;
    return status === 'cancelled' || status === 'paused';
  };

  const worker = async () => {
    while (!stopped()) {
      const item = claimNextItem(jobId);
      if (!item) return;
      if (stopped()) {
        requeueItem(jobId, item.idx);
        return;
      }
      const target = { target: item.target, type: item.type };
      try {
        const cached = options.reuseCache ? getCachedResult(user.id, target, options.freeSourcesOnly) : null;
        if (cached) {
          completeItem(jobId, item.idx, cached, true);
          continue;
        }
        const result = await analyzeTarget(
          { isValid: true, type: item.type, normalizedInput: item.target },
          createAnalysisContext(user, 'bulk', { freeSourcesOnly: options.freeSourcesOnly })
        );
        countLookup(user.id);
        putCachedResult(user.id, target, result, options.freeSourcesOnly);
        completeItem(jobId, item.idx, result, false);
      } catch (error) {
        console.error(`Bulk item ${item.target} failed:`, error);
        failItem(jobId, item.idx, error instanceof Error ? error.message : 'Analysis failed');
      }
    }
  };

  await Promise.all(Array.from({ length: WORKERS_PER_JOB }, worker));
  if (!stopped()) setJobStatus(jobId, 'done');
}
