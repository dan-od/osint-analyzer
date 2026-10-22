import { deleteUser, findConfirmedUserByEmail, listUsersForAdmin, updateProfile } from '@/lib/server/auth/users';
import { clearSessionCookie } from '@/lib/server/auth/session';
import { sendVerification, type Delivery } from '@/lib/server/auth/verification';
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

  const existing = findConfirmedUserByEmail(email);
  if (existing && existing.id !== auth.user.id) return jsonError('Another account already uses that email', 409);

  // A new address only takes effect once its confirmation link is used, so an
  // account can never hold an address it hasn't proved it owns
  const user = updateProfile(auth.user.id, name, auth.user.email);
  if (email === auth.user.email.toLowerCase()) return jsonOk({ user, pendingEmail: null, delivery: null });
  let delivery: Delivery | 'failed';
  try {
    delivery = await sendVerification('email-change', user, email);
  } catch (error) {
    console.error('[verification] Resend send failed:', (error as Error).message);
    delivery = 'failed';
  }
  return jsonOk({ user, pendingEmail: email, delivery });
}

/**
 * Delete my account: the user row, and with it (ON DELETE CASCADE) every
 * session, linked Google/GitHub account, saved API key, cached result,
 * recent check and bulk job. The body must repeat the account's email.
 */
export async function DELETE(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const body = await readJson<{ confirm: string }>(request);
  const confirm = typeof body?.confirm === 'string' ? body.confirm.trim().toLowerCase() : '';
  if (confirm !== auth.user.email.toLowerCase()) return jsonError('Type your email address exactly to confirm', 400);
  if (auth.user.role === 'admin' && listUsersForAdmin().filter((u) => u.role === 'admin').length <= 1) {
    return jsonError('You are the only admin, so this account can’t be deleted.', 409);
  }

  deleteUser(auth.user.id);
  const res = jsonOk({ deleted: true });
  clearSessionCookie(res);
  return res;
}
