import crypto from 'crypto';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import type { NextResponse } from 'next/server';
import { getDb } from '../db';
import { findUserById } from './users';
import type { PublicUser } from '@/types/account';

export const SESSION_COOKIE = 'osint_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function cookieSecure(): boolean {
  if (process.env.COOKIE_SECURE === 'false') return false;
  if (process.env.COOKIE_SECURE === 'true') return true;
  return process.env.NODE_ENV === 'production';
}

export function createSession(userId: number): { token: string; expiresAt: number } {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const db = getDb();
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(hashToken(token), userId, now, expiresAt);
  return { token, expiresAt };
}

export function deleteSession(token: string): void {
  getDb().prepare('DELETE FROM sessions WHERE id = ?').run(hashToken(token));
}

function userForToken(token: string | undefined): PublicUser | null {
  if (!token) return null;
  const row = getDb()
    .prepare('SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?')
    .get(hashToken(token), Date.now()) as { user_id: number } | undefined;
  return row ? findUserById(row.user_id) : null;
}

export function setSessionCookie(res: NextResponse, token: string, expiresAt: number): void {
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: 'lax',
    path: '/',
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set(SESSION_COOKIE, '', {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

export function getSessionToken(): string | undefined {
  return cookies().get(SESSION_COOKIE)?.value;
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

/** After a password change: sign out every other browser */
export function deleteOtherSessions(userId: number, keepToken: string | undefined): void {
  const keep = keepToken ? hashToken(keepToken) : '';
  getDb().prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').run(userId, keep);
}
