import { hashPassword, validatePassword } from '@/lib/server/auth/password';
import { createUser, findConfirmedUserByEmail, findUnconfirmedSignup, restartUnverifiedSignup } from '@/lib/server/auth/users';
import { sendVerification, type Delivery } from '@/lib/server/auth/verification';
import { checkSameOrigin, clientAddress, jsonError, jsonOk, readJson } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';
import { EMAIL_PATTERN } from '@/lib/validation';
import { SIGNUPS_PER_HOUR } from '@/lib/bulk-limits';

/**
 * Creates an unconfirmed password account and emails a confirmation link.
 * The account can't sign in (or be linked to Google/GitHub) until the link
 * is used. Google and GitHub signups don't come through here.
 */
export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  const limit = hitLimit(`signup:${clientAddress(request)}`, SIGNUPS_PER_HOUR, 60 * 60 * 1000);
  if (!limit.ok) {
    return jsonError('Too many signups from your network. Try again later.', 429, {
      'Retry-After': String(limit.retryAfterSec),
    });
  }

  const body = await readJson<{ name: string; email: string; password: string }>(request);
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';

  if (!name || name.length > 100) return jsonError('Please enter your name (max 100 characters)', 400);
  if (!EMAIL_PATTERN.test(email) || email.length > 254) return jsonError('Please enter a valid email address', 400);
  const passwordError = validatePassword(password);
  if (passwordError) return jsonError(passwordError, 400);

  if (findConfirmedUserByEmail(email)) {
    return jsonError('An account with this email already exists. Log in, or use Google or GitHub if that is how you signed up.', 409);
  }
  const existing = findUnconfirmedSignup(email);

  const passwordHash = await hashPassword(password);
  let user: { id: number; name: string };
  if (existing) {
    // Still unconfirmed: start that signup over (the old link stops working)
    restartUnverifiedSignup(existing.id, name, passwordHash);
    user = { id: existing.id, name };
  } else {
    user = createUser(name, email, passwordHash, false);
  }

  let delivery: Delivery | 'failed';
  try {
    delivery = await sendVerification('signup', user, email);
  } catch (error) {
    console.error('[verification] Resend send failed:', (error as Error).message);
    delivery = 'failed';
  }
  return jsonOk({ email, delivery }, { status: 201 });
}
