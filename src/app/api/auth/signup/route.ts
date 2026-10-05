import crypto from 'crypto';
import { hashPassword, validatePassword } from '@/lib/server/auth/password';
import { createUser, emailExists } from '@/lib/server/auth/users';
import { createSession, setSessionCookie } from '@/lib/server/auth/session';
import { checkSameOrigin, clientAddress, jsonError, jsonOk, readJson } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';
import { EMAIL_PATTERN } from '@/lib/validation';

function inviteCodeMatches(provided: string, expected: string): boolean {
  // Compare digests so the comparison is constant-time regardless of length
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  const limit = hitLimit(`signup:${clientAddress(request)}`, 10, 60 * 60 * 1000);
  if (!limit.ok) {
    return jsonError('Too many signup attempts. Try again later.', 429, {
      'Retry-After': String(limit.retryAfterSec),
    });
  }

  const expectedInvite = process.env.INVITE_CODE?.trim();
  if (!expectedInvite) return jsonError('Signups are currently closed', 403);

  const body = await readJson<{ name: string; email: string; password: string; inviteCode: string }>(request);
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  const inviteCode = typeof body?.inviteCode === 'string' ? body.inviteCode.trim() : '';

  if (!inviteCode || !inviteCodeMatches(inviteCode, expectedInvite)) {
    return jsonError('Invalid invite code', 403);
  }
  if (!name || name.length > 100) return jsonError('Please enter your name (max 100 characters)', 400);
  if (!EMAIL_PATTERN.test(email) || email.length > 254) return jsonError('Please enter a valid email address', 400);
  const passwordError = validatePassword(password);
  if (passwordError) return jsonError(passwordError, 400);

  if (emailExists(email)) return jsonError('An account with this email already exists', 409);

  const user = createUser(name, email, await hashPassword(password));
  const session = createSession(user.id);
  const res = jsonOk({ user }, { status: 201 });
  setSessionCookie(res, session.token, session.expiresAt);
  return res;
}
