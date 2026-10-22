import { parseBulkInput } from '@/lib/bulk-input';
import { createJob, hasActiveJob, listJobs } from '@/lib/server/bulk/jobs';
import { resumeBulkJobs, startJob } from '@/lib/server/bulk/worker';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiUser } from '@/lib/server/http';
import { DEFAULT_BULK_OPTIONS, type BulkOptions, type BulkTarget } from '@/types/bulk';

export const dynamic = 'force-dynamic';

const MAX_INPUT_CHARS = 2_000_000;

export async function GET() {
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  resumeBulkJobs();
  return jsonOk({ jobs: listJobs(auth.user.id) }, { headers: { 'Cache-Control': 'no-store' } });
}

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  resumeBulkJobs();

  const body = await readJson<{ input: string; name: string; options: Partial<BulkOptions> }>(request);
  const input = typeof body?.input === 'string' ? body.input : '';
  if (!input.trim()) return jsonError('Paste some IPs or domains, or upload a CSV', 400);
  if (input.length > MAX_INPUT_CHARS) return jsonError('Input is too large', 413);

  const options: BulkOptions = {
    skipInternal: body?.options?.skipInternal ?? DEFAULT_BULK_OPTIONS.skipInternal,
    reuseCache: body?.options?.reuseCache ?? DEFAULT_BULK_OPTIONS.reuseCache,
    freeSourcesOnly: body?.options?.freeSourcesOnly ?? DEFAULT_BULK_OPTIONS.freeSourcesOnly,
  };
  const name = typeof body?.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 120) : 'Pasted list';

  if (hasActiveJob(auth.user.id)) {
    return jsonError('You already have a bulk job running. Wait for it to finish, or cancel it first.', 409);
  }

  // New accounts get a smaller per-job cap until an admin raises it
  const maxTargets = auth.user.bulkCap;
  const parsed = parseBulkInput(input, maxTargets);
  const internal: BulkTarget[] = parsed.internal.map((target) => ({ target, type: 'ip' }));
  // With the option off, internal IPs are queued; they still never leave the server
  const targets = options.skipInternal ? parsed.targets : [...parsed.targets, ...internal].slice(0, maxTargets);
  if (targets.length === 0 && internal.length === 0) {
    return jsonError('No IP addresses or domains found in the input', 400);
  }

  const jobId = createJob(auth.user.id, {
    name,
    options,
    pasted: parsed.candidates,
    targets,
    skippedInternal: options.skipInternal ? internal : [],
  });
  startJob(jobId);
  return jsonOk(
    {
      jobId,
      queued: targets.length,
      skipped: {
        duplicates: parsed.duplicates,
        internal: parsed.internal.length,
        unsupported: parsed.unsupported.length,
        invalid: parsed.invalid.length,
        truncated: parsed.truncated,
      },
    },
    { status: 201 }
  );
}
