// Shared checks for the single-lookup endpoints (plain JSON and streaming)
import { NextResponse } from 'next/server';
import { validateInput } from '@/lib/utils';
import { internalIpReason, parseIp } from '@/lib/ip';
import { getCurrentUser } from '../auth/session';
import { clientAddress } from '../http';
import { hitLimit } from '../rate-limit';
import type { PublicUser } from '@/types/account';
import type { ValidationResult } from '@/types';

import { ANONYMOUS_CHECKS_PER_HOUR } from '@/lib/bulk-limits';

type Prepared =
  | { ok: true; user: PublicUser | null; validation: ValidationResult & { type: NonNullable<ValidationResult['type']> } }
  | { ok: false; response: NextResponse };

const fail = (error: string, status: number, headers?: HeadersInit): Prepared => ({
  ok: false,
  response: NextResponse.json({ success: false, error }, { status, headers }),
});

export function prepareCheck(request: Request, query: unknown): Prepared {
  if (!query || typeof query !== 'string') return fail('Query is required', 400);

  const validation = validateInput(query);
  if (!validation.isValid || !validation.type) return fail(validation.error || 'Invalid input', 400);

  const user = getCurrentUser();
  // Private/reserved addresses are answered locally, so they don't need an account
  const ip = validation.type === 'ip' ? parseIp(validation.normalizedInput) : null;
  if (validation.type === 'ip' && !user && !(ip && internalIpReason(ip))) {
    return fail('IP checks need an account. Log in to check IP addresses.', 401);
  }
  if (!user) {
    const limit = hitLimit(`anon-check:${clientAddress(request)}`, ANONYMOUS_CHECKS_PER_HOUR, 60 * 60 * 1000);
    if (!limit.ok) {
      return fail(
        `Logged-out checks are limited to ${ANONYMOUS_CHECKS_PER_HOUR} an hour. Try again in ${Math.ceil(limit.retryAfterSec / 60)} min, or log in.`,
        429,
        { 'Retry-After': String(limit.retryAfterSec) }
      );
    }
  }
  return { ok: true, user, validation: { ...validation, type: validation.type } };
}
