'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { parseBulkInput } from '@/lib/bulk-input';
import { takeBulkInput } from '@/lib/client/bulk-handoff';
import {
  bulkExportUrl,
  cancelBulkJob,
  fetchBulkItem,
  fetchBulkJob,
  listBulkJobs,
  setBulkJobPaused,
  startBulkJob,
  type StartBulkResponse,
} from '@/lib/client/bulk';
import type { AnalysisResult } from '@/types';
import { DEFAULT_BULK_OPTIONS, type BulkItemSummary, type BulkJobDetail, type BulkJobSummary, type BulkOptions } from '@/types/bulk';

const POLL_MS = 2000;

export type BulkFilter = 'all' | 'flagged' | 'clean' | 'pending' | 'errors';
export type ScoreSort = 'desc' | 'asc';

const isActive = (job: { status: string } | null) => job?.status === 'queued' || job?.status === 'running';

const isFlagged = (i: BulkItemSummary) => i.status === 'done' && !!i.riskLevel && i.riskLevel !== 'low';

function matches(item: BulkItemSummary, filter: BulkFilter): boolean {
  switch (filter) {
    case 'flagged':
      return isFlagged(item);
    case 'clean':
      return item.status === 'done' && !isFlagged(item);
    case 'pending':
      return item.status === 'queued' || item.status === 'running';
    case 'errors':
      return item.status === 'error';
    default:
      return true;
  }
}

/** Highest score first by default; unfinished rows always sink */
function sortItems(items: BulkItemSummary[], sort: ScoreSort): BulkItemSummary[] {
  return [...items].sort((a, b) => {
    if (a.riskScore === null) return b.riskScore === null ? a.idx - b.idx : 1;
    if (b.riskScore === null) return -1;
    return sort === 'desc' ? b.riskScore - a.riskScore || a.idx - b.idx : a.riskScore - b.riskScore || a.idx - b.idx;
  });
}

export function useBulk(initialJobId: string | null, maxTargets: number) {
  // Input
  const [input, setInput] = useState('');
  const [name, setName] = useState('Pasted list');
  const [options, setOptions] = useState<BulkOptions>(DEFAULT_BULK_OPTIONS);
  const preview = useMemo(() => parseBulkInput(input, maxTargets), [input, maxTargets]);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [lastSubmit, setLastSubmit] = useState<StartBulkResponse | null>(null);

  // Jobs
  const [jobs, setJobs] = useState<BulkJobSummary[]>([]);
  const [jobId, setJobId] = useState<string | null>(initialJobId);
  const [job, setJob] = useState<BulkJobDetail | null>(null);
  const [jobError, setJobError] = useState<string | null>(null);
  const [filter, setFilter] = useState<BulkFilter>('all');
  const [sort, setSort] = useState<ScoreSort>('desc');

  // Row detail
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [selected, setSelected] = useState<AnalysisResult | null>(null);
  const [selectedError, setSelectedError] = useState<string | null>(null);

  const refreshJobs = useCallback(async () => {
    try {
      const list = await listBulkJobs();
      setJobs(list);
      return list;
    } catch {
      return [];
    }
  }, []);

  // A list handed over from the dashboard, then the most recent job
  useEffect(() => {
    const handoff = takeBulkInput();
    if (handoff) {
      setInput(handoff.text);
      setName(handoff.name);
    }
    void refreshJobs().then((list) => {
      if (list[0]) setJobId((current) => current ?? list[0].id);
    });
  }, [refreshJobs]);

  // Load the selected job, polling while it runs
  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      try {
        const detail = await fetchBulkJob(jobId);
        if (cancelled) return;
        setJob(detail);
        setJobError(null);
        if (isActive(detail)) timer = setTimeout(load, POLL_MS);
        else void refreshJobs();
      } catch (err) {
        if (!cancelled) setJobError(err instanceof Error ? err.message : 'Could not load the job');
      }
    };
    void load();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [jobId, refreshJobs]);

  useEffect(() => {
    setSelected(null);
    setSelectedError(null);
    if (!jobId || selectedIdx === null) return;
    let cancelled = false;
    fetchBulkItem(jobId, selectedIdx)
      .then((result) => !cancelled && setSelected(result))
      .catch((err) => !cancelled && setSelectedError(err instanceof Error ? err.message : 'Could not load result'));
    return () => {
      cancelled = true;
    };
  }, [jobId, selectedIdx]);

  const start = async () => {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const response = await startBulkJob(input, name, options);
      setLastSubmit(response);
      setSelectedIdx(null);
      setJob(null);
      setFilter('all');
      setJobId(response.jobId);
      setInput('');
      setName('Pasted list');
      window.history.replaceState(null, '', `/bulk?job=${response.jobId}`);
      void refreshJobs();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Could not start the job');
    } finally {
      setSubmitting(false);
    }
  };

  const loadFile = async (file: File) => {
    setInput(await file.text());
    setName(file.name);
  };

  const control = async (action: () => Promise<BulkJobDetail>) => {
    try {
      const detail = await action();
      setJob(detail);
      void refreshJobs();
    } catch (err) {
      setJobError(err instanceof Error ? err.message : 'That did not work');
    }
  };

  const openJob = (id: string) => {
    setSelectedIdx(null);
    setJob(null);
    setFilter('all');
    setJobId(id);
    window.history.replaceState(null, '', `/bulk?job=${id}`);
  };

  const items = useMemo(() => (job ? sortItems(job.items.filter((i) => matches(i, filter)), sort) : []), [job, filter, sort]);

  return {
    input: {
      value: input,
      setValue: (v: string) => {
        setInput(v);
        if (!v.trim()) setName('Pasted list');
      },
      name,
      loadFile,
      preview,
      options,
      setOption: (key: keyof BulkOptions, value: boolean) => setOptions((o) => ({ ...o, [key]: value })),
      start,
      submitting,
      submitError,
      lastSubmit,
    },
    jobs,
    job,
    jobError,
    jobActive: isActive(job),
    jobBusy: isActive(job) || job?.status === 'paused',
    items,
    filter,
    setFilter: (f: BulkFilter) => setFilter((current) => (current === f ? 'all' : f)),
    sort,
    toggleSort: () => setSort((s) => (s === 'desc' ? 'asc' : 'desc')),
    openJob,
    pause: () => jobId && control(() => setBulkJobPaused(jobId, true)),
    resume: async () => {
      if (!jobId) return;
      await control(() => setBulkJobPaused(jobId, false));
      setJobId(null);
      setTimeout(() => setJobId(jobId), 0);
    },
    cancel: () => jobId && control(() => cancelBulkJob(jobId)),
    exportUrl: jobId ? bulkExportUrl(jobId) : null,
    selection: { idx: selectedIdx, select: setSelectedIdx, result: selected, error: selectedError },
  };
}
