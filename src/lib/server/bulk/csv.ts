import { toCsv } from '@/lib/csv';
import type { BulkJobDetail } from '@/types/bulk';

/** One row per target: done, failed, skipped (internal) or still pending */
export function bulkJobToCsv(job: BulkJobDetail): string {
  return toCsv(
    job.items.map((item) => {
      const f = item.facts;
      const verdict =
        item.status === 'done'
          ? f?.verdict
          : item.status === 'error'
            ? `Error: ${item.error ?? 'failed'}`
            : item.status === 'skipped'
              ? 'Internal IP – not checked'
              : item.status;
      return [
        item.target,
        verdict,
        item.riskScore,
        f?.abuseScore,
        f?.vtDetections,
        f?.blocklistHits,
        f?.proxyType,
        f?.country,
        f?.topFinding,
      ];
    })
  );
}
