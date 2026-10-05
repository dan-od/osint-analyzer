// Small helpers shared by the API route handlers
import { NextResponse } from 'next/server';
import { getCurrentUser } from './auth/session';
import type { PublicUser } from '@/types/account';

export function jsonOk<T>(data: T, init?: ResponseInit): NextResponse {
  return NextResponse.json({ success: true, data, timestamp: new Date().toISOString() }, init);
}

export function jsonError(error: string, status: number, headers?: HeadersInit): NextResponse {
  return NextResponse.json(
    { success: false, error, timestamp: new Date().toISOString() },
    { status, headers }
  );
}

/**
 * Rejects cross-site state-changing requests. Session cookies are SameSite=Lax
 * already; this is a second layer for browsers that send an Origin header.
 */
export function checkSameOrigin(request: Request): NextResponse | null {
  const origin = request.headers.get('origin');
  if (!origin) return null;
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host');
  try {
    if (host && new URL(origin).host === host) return null;
  } catch {
    // malformed Origin header
  }
  return jsonError('Cross-site request blocked', 403);
}

export function clientAddress(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  return forwarded?.split(',')[0]?.trim() || request.headers.get('x-real-ip') || 'unknown';
}

/** Returns the user, or a 401 response for the handler to return. */
export function requireApiUser(): { user: PublicUser } | { response: NextResponse } {
  const user = getCurrentUser();
  return user ? { user } : { response: jsonError('Please log in to continue', 401) };
}

export async function readJson<T>(request: Request): Promise<Partial<T> | null> {
  try {
    const body = await request.json();
    return body && typeof body === 'object' ? (body as Partial<T>) : null;
  } catch {
    return null;
  }
}
