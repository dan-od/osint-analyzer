import { cancelJob, getJobDetail, pauseJob, resumeJob } from '@/lib/server/bulk/jobs';
import { resumeBulkJobs, startJob } from '@/lib/server/bulk/worker';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiUser } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

type Params = { params: { id: string } };

export async function GET(_request: Request, { params }: Params) {
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  resumeBulkJobs();
  const job = getJobDetail(auth.user.id, params.id);
  if (!job) return jsonError('Bulk job not found', 404);
  return jsonOk(job, { headers: { 'Cache-Control': 'no-store' } });
}

/** { action: 'pause' | 'resume' } */
export async function PATCH(request: Request, { params }: Params) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const body = await readJson<{ action: string }>(request);
  if (body?.action === 'pause') {
    if (!pauseJob(auth.user.id, params.id)) return jsonError('Job is not running', 409);
  } else if (body?.action === 'resume') {
    if (!resumeJob(auth.user.id, params.id)) return jsonError('Job is not paused', 409);
    startJob(params.id);
  } else {
    return jsonError('Unknown action', 400);
  }
  return jsonOk(getJobDetail(auth.user.id, params.id));
}

/** Cancels the job; items already finished are kept. */
export async function DELETE(request: Request, { params }: Params) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  if (!cancelJob(auth.user.id, params.id)) return jsonError('Job not found or already finished', 404);
  return jsonOk(getJobDetail(auth.user.id, params.id));
}
