// Sessions. Auth.js (src/auth.ts) runs every sign-in; each one gets a row in
// the Auth.js `sessions` table, and the session cookie carries a random token
// for that row (not a JWT), so signing out, disabling an account or changing a
// password ends sessions at once. Pages and API routes read the cookie here,
// synchronously, without going through Auth.js.
import crypto from 'crypto';
import { cookies } from 'next/headers';
import { notFound, redirect } from 'next/navigation';
import type { NextResponse } from 'next/server';
import { getDb } from '../db';
import { RETENTION } from '@/lib/retention';
import { findUserById, touchLastActive } from './users';
import type { PublicUser } from '@/types/account';

/** Auth.js cookie names: the __Secure- one is used over HTTPS */
export const SESSION_COOKIES = ['__Secure-authjs.session-token', 'authjs.session-token'] as const;
export const SESSION_MAX_AGE_SECONDS = RETENTION.sessionDays * 24 * 60 * 60;

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** A session token is opaque base64url; Auth.js's own JWTs contain dots */
export function isSessionToken(value: string | undefined): value is string {
  return !!value && /^[A-Za-z0-9_-]{40,}$/.test(value);
}

export function createSession(userId: number): { token: string; expiresAt: number } {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const expiresAt = now + SESSION_MAX_AGE_SECONDS * 1000;
  const db = getDb();
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(now);
  db.prepare('INSERT INTO sessions (id, session_token, user_id, expires, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(crypto.randomUUID(), hashToken(token), userId, expiresAt, now);
  return { token, expiresAt };
}

export function deleteSession(token: string): void {
  getDb().prepare('DELETE FROM sessions WHERE session_token = ?').run(hashToken(token));
}

export function deleteAllSessions(userId: number): void {
  getDb().prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

/** The user id behind a live session token, or null (expired, unknown, or account disabled) */
export function sessionUserId(token: string): number | null {
  const row = getDb()
    .prepare(
      `SELECT s.user_id FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.session_token = ? AND s.expires > ? AND u.disabled = 0`
    )
    .get(hashToken(token), Date.now()) as { user_id: number } | undefined;
  return row?.user_id ?? null;
}

function userForToken(token: string | undefined): PublicUser | null {
  if (!isSessionToken(token)) return null;
  const userId = sessionUserId(token);
  const user = userId ? findUserById(userId) : null;
  if (user) touchLastActive(user.id);
  return user;
}

/**
 * Signs a user in outside Auth.js (after confirming an email). Same cookie
 * Auth.js would set: the __Secure- name and Secure flag when the site is HTTPS.
 */
export function startSession(res: NextResponse, request: Request, userId: number): void {
  const { token, expiresAt } = createSession(userId);
  const https =
    (process.env.AUTH_URL?.trim() ?? '').startsWith('https://') ||
    request.headers.get('x-forwarded-proto') === 'https' ||
    new URL(request.url).protocol === 'https:';
  res.cookies.set(https ? SESSION_COOKIES[0] : SESSION_COOKIES[1], token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: https,
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(res: NextResponse): void {
  for (const name of SESSION_COOKIES) {
    res.cookies.set(name, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, secure: name.startsWith('__Secure-') });
  }
}

export function getSessionToken(): string | undefined {
  const jar = cookies();
  for (const name of SESSION_COOKIES) {
    const value = jar.get(name)?.value;
    if (value) return value;
  }
  return undefined;
}

/** The logged-in user for the current request (route handlers and server components). */
export function getCurrentUser(): PublicUser | null {
  return userForToken(getSessionToken());
}

/** For protected pages: sends anonymous visitors to the login page. */
export function requireUser(returnTo: string): PublicUser {
  const user = getCurrentUser();
  if (!user) redirect(`/login?next=${encodeURIComponent(returnTo)}`);
  return user;
}

/** For admin pages: anyone else gets a plain 404 */
export function requireAdmin(returnTo: string): PublicUser {
  const user = requireUser(returnTo);
  if (user.role !== 'admin') notFound();
  return user;
}

/** After a password change: sign out every other browser */
export function deleteOtherSessions(userId: number, keepToken: string | undefined): void {
  const keep = keepToken ? hashToken(keepToken) : '';
  getDb().prepare('DELETE FROM sessions WHERE user_id = ? AND session_token != ?').run(userId, keep);
}
