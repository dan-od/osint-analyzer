import { burnPasswordCheck, verifyPassword } from '@/lib/server/auth/password';
import { findUserByEmail } from '@/lib/server/auth/users';
import { createSession, setSessionCookie } from '@/lib/server/auth/session';
import { checkSameOrigin, clientAddress, jsonError, jsonOk, readJson } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';

const INVALID = 'Invalid email or password';

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  const body = await readJson<{ email: string; password: string }>(request);
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!email || !password) return jsonError('Email and password are required', 400);

  const ipLimit = hitLimit(`login-ip:${clientAddress(request)}`, 30, 15 * 60 * 1000);
  const emailLimit = hitLimit(`login-email:${email}`, 10, 15 * 60 * 1000);
  if (!ipLimit.ok || !emailLimit.ok) {
    const retry = Math.max(ipLimit.retryAfterSec, emailLimit.retryAfterSec);
    return jsonError('Too many login attempts. Try again later.', 429, { 'Retry-After': String(retry) });
  }

  const user = findUserByEmail(email);
  if (!user) {
    await burnPasswordCheck(password);
    return jsonError(INVALID, 401);
  }
  if (!(await verifyPassword(password, user.passwordHash))) return jsonError(INVALID, 401);

  const { passwordHash: _hash, ...publicUser } = user;
  const session = createSession(user.id);
  const res = jsonOk({ user: publicUser });
  setSessionCookie(res, session.token, session.expiresAt);
  return res;
}
