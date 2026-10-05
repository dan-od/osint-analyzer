import { apiRequest } from './http';
import type { AnalysisResult } from '@/types';
import type { BulkJobDetail, BulkJobSummary, BulkOptions } from '@/types/bulk';

export interface StartBulkResponse {
  jobId: string;
  queued: number;
  skipped: { duplicates: number; internal: number; unsupported: number; invalid: number; truncated: number };
}

export function startBulkJob(input: string, name: string, options: BulkOptions): Promise<StartBulkResponse> {
  return apiRequest<StartBulkResponse>('/api/bulk', { method: 'POST', body: JSON.stringify({ input, name, options }) });
}

export async function listBulkJobs(): Promise<BulkJobSummary[]> {
  return (await apiRequest<{ jobs: BulkJobSummary[] }>('/api/bulk', { cache: 'no-store' })).jobs;
}

export function fetchBulkJob(jobId: string): Promise<BulkJobDetail> {
  return apiRequest<BulkJobDetail>(`/api/bulk/${jobId}`, { cache: 'no-store' });
}

export function cancelBulkJob(jobId: string): Promise<BulkJobDetail> {
  return apiRequest<BulkJobDetail>(`/api/bulk/${jobId}`, { method: 'DELETE' });
}

export function setBulkJobPaused(jobId: string, paused: boolean): Promise<BulkJobDetail> {
  return apiRequest<BulkJobDetail>(`/api/bulk/${jobId}`, {
    method: 'PATCH',
    body: JSON.stringify({ action: paused ? 'pause' : 'resume' }),
  });
}

export function fetchBulkItem(jobId: string, idx: number): Promise<AnalysisResult> {
  return apiRequest<AnalysisResult>(`/api/bulk/${jobId}/items/${idx}`);
}

export function bulkExportUrl(jobId: string): string {
  return `/api/bulk/${jobId}/export`;
}
