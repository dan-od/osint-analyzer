import { getItemResult } from '@/lib/server/bulk/jobs';
import { jsonError, jsonOk, requireApiUser } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

export async function GET(_request: Request, { params }: { params: { id: string; idx: string } }) {
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;
  const idx = Number(params.idx);
  if (!Number.isInteger(idx) || idx < 0) return jsonError('Invalid item', 400);
  const result = getItemResult(auth.user.id, params.id, idx);
  if (!result) return jsonError('Result not available', 404);
  return jsonOk(result);
}
