import { hashPassword, validatePassword, verifyPassword } from '@/lib/server/auth/password';
import { getPasswordHash, setPasswordHash } from '@/lib/server/auth/users';
import { deleteOtherSessions, getSessionToken } from '@/lib/server/auth/session';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiUser } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const limit = hitLimit(`password-change:${auth.user.id}`, 10, 15 * 60 * 1000);
  if (!limit.ok) return jsonError('Too many attempts. Try again later.', 429, { 'Retry-After': String(limit.retryAfterSec) });

  const body = await readJson<{ current: string; next: string }>(request);
  const current = typeof body?.current === 'string' ? body.current : '';
  const next = typeof body?.next === 'string' ? body.next : '';

  const hash = getPasswordHash(auth.user.id);
  if (!hash || !(await verifyPassword(current, hash))) return jsonError('Your current password is not right', 403);
  const problem = validatePassword(next);
  if (problem) return jsonError(problem, 400);

  setPasswordHash(auth.user.id, await hashPassword(next));
  deleteOtherSessions(auth.user.id, getSessionToken());
  return jsonOk({ changed: true });
}
