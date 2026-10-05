import { getJobDetail } from '@/lib/server/bulk/jobs';
import { bulkJobToCsv } from '@/lib/server/bulk/csv';
import { jsonError, requireApiUser } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

export async function GET(_request: Request, { params }: { params: { id: string } }) {
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  const job = getJobDetail(auth.user.id, params.id);
  if (!job) return jsonError('Bulk job not found', 404);

  const date = job.createdAt.slice(0, 10);
  return new Response(bulkJobToCsv(job), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="osint-bulk-${date}-${job.id.slice(0, 8)}.csv"`,
      'Cache-Control': 'no-store',
    },
  });
}
