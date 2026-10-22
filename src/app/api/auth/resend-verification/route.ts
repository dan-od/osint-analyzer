// Sends a fresh confirmation link to an unconfirmed password signup. The
// answer is the same whether or not such an account exists.
import { findUnconfirmedSignup } from '@/lib/server/auth/users';
import { sendVerification, type Delivery } from '@/lib/server/auth/verification';
import { mailConfigured } from '@/lib/server/mail';
import { checkSameOrigin, clientAddress, jsonError, jsonOk, readJson } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';
import { RESENDS_PER_HOUR, RESENDS_PER_HOUR_PER_IP } from '@/lib/bulk-limits';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  const body = await readJson<{ email: string }>(request);
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!email) return jsonError('Enter the email address you signed up with', 400);

  const ipLimit = hitLimit(`resend-ip:${clientAddress(request)}`, RESENDS_PER_HOUR_PER_IP, 60 * 60 * 1000);
  const emailLimit = hitLimit(`resend-email:${email}`, RESENDS_PER_HOUR, 60 * 60 * 1000);
  if (!ipLimit.ok || !emailLimit.ok) {
    const retry = Math.max(ipLimit.retryAfterSec, emailLimit.retryAfterSec);
    return jsonError(`Too many links requested. Try again in ${Math.ceil(retry / 60)} minutes.`, 429, { 'Retry-After': String(retry) });
  }

  const user = findUnconfirmedSignup(email);
  let delivery: Delivery | 'failed' = mailConfigured() ? 'email' : 'console';
  if (user) {
    try {
      delivery = await sendVerification('signup', user, email);
    } catch (error) {
      console.error('[verification] Resend send failed:', (error as Error).message);
      delivery = 'failed';
    }
  }
  return jsonOk({ email, delivery });
}
