// Uses a confirmation link and signs the person in. POST only (the page has a
// form), so mail scanners that open links can't use it up or get a session.
// A signup also needs its password: a wrong one counts against the link and
// does not use it; the link locks after VERIFY_MAX_ATTEMPTS wrong tries.
import { consumeToken } from '@/lib/server/auth/verification';
import { getCurrentUser, startSession } from '@/lib/server/auth/session';
import { userStatus } from '@/lib/server/auth/users';
import { checkSameOrigin, clientAddress, jsonError, jsonOk, readJson } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';

export const dynamic = 'force-dynamic';

// Status codes the confirm page switches on
const FAILURES = {
  wrong_password: { status: 401, message: 'That password doesn’t match this signup. Check it and try again.' },
  locked: { status: 423, message: 'Too many wrong passwords, so this link no longer works. Ask for a new one below.' },
  not_signed_in: { status: 403, message: 'Log in to the account first, then open this link again to confirm the change.' },
  invalid: { status: 410, message: 'This link isn’t valid. It may have been replaced by a newer one.' },
  used: { status: 410, message: 'This link has already been used.' },
  expired: { status: 410, message: 'This link has expired.' },
  taken: { status: 409, message: 'Another account now uses that email address, so it can’t be moved to yours.' },
};

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  // Per-link attempts are counted in the database; this also slows one
  // address trying many links
  const limit = hitLimit(`verify-ip:${clientAddress(request)}`, 30, 15 * 60 * 1000);
  if (!limit.ok) return jsonError('Too many attempts. Try again later.', 429, { 'Retry-After': String(limit.retryAfterSec) });

  const body = await readJson<{ token: string; password: string }>(request);
  const result = await consumeToken(typeof body?.token === 'string' ? body.token : '', {
    password: typeof body?.password === 'string' ? body.password : undefined,
    signedInUserId: getCurrentUser()?.id ?? null,
  });
  if (!result.ok) {
    const failure = FAILURES[result.reason];
    return jsonError(failure.message, failure.status);
  }

  const signedIn = !userStatus(result.userId)?.disabled;
  const res = jsonOk({ purpose: result.purpose, email: result.email, merged: result.merged, signedIn });
  if (signedIn) startSession(res, request, result.userId);
  return res;
}
