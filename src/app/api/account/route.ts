import { findUserByEmail, updateProfile } from '@/lib/server/auth/users';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiUser } from '@/lib/server/http';
import { EMAIL_PATTERN } from '@/lib/validation';

export const dynamic = 'force-dynamic';

/** Update name and email */
export async function PATCH(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const body = await readJson<{ name: string; email: string }>(request);
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!name || name.length > 100) return jsonError('Please enter your name (max 100 characters)', 400);
  if (!EMAIL_PATTERN.test(email) || email.length > 254) return jsonError('Please enter a valid email address', 400);

  const existing = findUserByEmail(email);
  if (existing && existing.id !== auth.user.id) return jsonError('Another account already uses that email', 409);

  return jsonOk({ user: updateProfile(auth.user.id, name, email) });
}
