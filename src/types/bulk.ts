import type { ResultFacts, RiskLevel } from './index';

export type BulkTargetType = 'ip' | 'domain';

export interface BulkTarget {
  target: string;
  type: BulkTargetType;
}

export interface BulkParseResult {
  targets: BulkTarget[];
  duplicates: number;
  /** Private/reserved IPs, removed before queueing */
  internal: string[];
  /** Recognised but not supported in bulk (emails, phone numbers, wallets) */
  unsupported: string[];
  invalid: string[];
  /** Targets dropped because the list was over the limit */
  truncated: number;
}

export type BulkJobStatus = 'queued' | 'running' | 'paused' | 'done' | 'cancelled';
/** skipped = private/reserved IP, never looked up */
export type BulkItemStatus = 'queued' | 'running' | 'done' | 'error' | 'skipped' | 'cancelled';

export interface BulkOptions {
  /** Drop private and reserved IPs before lookup (listed as skipped) */
  skipInternal: boolean;
  /** Reuse results from the last 24 hours */
  reuseCache: boolean;
  /** Skip every source that needs an API key */
  freeSourcesOnly: boolean;
}

export const DEFAULT_BULK_OPTIONS: BulkOptions = { skipInternal: true, reuseCache: true, freeSourcesOnly: false };

export interface BulkItemSummary {
  idx: number;
  target: string;
  type: BulkTargetType;
  status: BulkItemStatus;
  /** Served from the 24h result cache */
  cached: boolean;
  error: string | null;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  facts: ResultFacts | null;
}

export interface BulkJobSummary {
  id: string;
  /** Uploaded file name, or "Pasted list" */
  name: string;
  status: BulkJobStatus;
  options: BulkOptions;
  /** Values pasted before dedupe and filtering */
  pasted: number;
  total: number;
  /** Finished, failed or skipped */
  completed: number;
  failed: number;
  /** Done with a verdict above Low */
  flagged: number;
  clean: number;
  pending: number;
  skipped: number;
  createdAt: string;
}

export interface BulkJobDetail extends BulkJobSummary {
  items: BulkItemSummary[];
}
