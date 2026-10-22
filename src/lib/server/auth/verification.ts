// Email verification for password accounts, and for email changes.
//
// Tokens live in the Auth.js verification_tokens table, hashed (sha256), one
// live token per purpose: sending a new one deletes the unused old one. They
// expire after RETENTION.verificationLinkHours and work once (used_at is set,
// so a second click can say "already used" rather than "invalid").
//
// identifier is "signup:<userId>" or "email-change:<userId>:<new address>".
import crypto from 'crypto';
import { getDb } from '../db';
import { mailConfigured, mailLinkBase, mailLogoUrl, sendMail } from '../mail';
import { verificationEmail } from '../email/verification-email';
import { RETENTION } from '@/lib/retention';
import { VERIFY_MAX_ATTEMPTS } from '@/lib/bulk-limits';
import { verifyPassword } from './password';

export type VerificationPurpose = 'signup' | 'email-change';

/** How the link reached the user: by email, or only in the server log (no RESEND_API_KEY) */
export type Delivery = 'email' | 'console';

export type TokenProblem = 'invalid' | 'expired' | 'used' | 'locked';

const hash = (token: string) => crypto.createHash('sha256').update(token).digest('hex');

function identifierFor(purpose: VerificationPurpose, userId: number, email: string): string {
  return purpose === 'signup' ? `signup:${userId}` : `email-change:${userId}:${email}`;
}

/** New single-use token for this user and purpose; an unused earlier one stops working */
function createToken(purpose: VerificationPurpose, userId: number, email: string): string {
  const token = crypto.randomBytes(32).toString('base64url');
  const db = getDb();
  db.transaction(() => {
    const previous = purpose === 'signup' ? `signup:${userId}` : `email-change:${userId}:%`;
    db.prepare('DELETE FROM verification_tokens WHERE identifier LIKE ? AND used_at IS NULL').run(previous);
    db.prepare('INSERT INTO verification_tokens (identifier, token, expires) VALUES (?, ?, ?)').run(
      identifierFor(purpose, userId, email),
      hash(token),
      Date.now() + RETENTION.verificationLinkHours * 60 * 60 * 1000
    );
  })();
  return token;
}

export interface TokenInfo {
  purpose: VerificationPurpose;
  userId: number;
  email: string;
}

type Lookup = { ok: true; info: TokenInfo } | { ok: false; reason: TokenProblem };

function lookup(token: string): Lookup {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) return { ok: false, reason: 'invalid' };
  const row = getDb()
    .prepare('SELECT identifier, expires, used_at, failed_attempts FROM verification_tokens WHERE token = ?')
    .get(hash(token)) as { identifier: string; expires: number; used_at: number | null; failed_attempts: number } | undefined;
  if (!row) return { ok: false, reason: 'invalid' };
  if (row.used_at) return { ok: false, reason: 'used' };
  if (row.failed_attempts >= VERIFY_MAX_ATTEMPTS) return { ok: false, reason: 'locked' };
  if (row.expires < Date.now()) return { ok: false, reason: 'expired' };
  const [purpose, id, ...rest] = row.identifier.split(':');
  const userId = Number(id);
  const user = getDb().prepare('SELECT email FROM users WHERE id = ?').get(userId) as { email: string } | undefined;
  if (!user) return { ok: false, reason: 'invalid' };
  return {
    ok: true,
    info: { purpose: purpose as VerificationPurpose, userId, email: purpose === 'signup' ? user.email : rest.join(':') },
  };
}

/** Checks a link without using it (the confirm page shows what it will do) */
export function peekToken(token: string): Lookup {
  return lookup(token);
}

export type ConsumeResult =
  | { ok: true; purpose: VerificationPurpose; email: string; userId: number; merged: boolean }
  | { ok: false; reason: TokenProblem | 'taken' | 'wrong_password' | 'not_signed_in' };

/**
 * Uses the token, after proving it's the right person:
 * - signup: the password chosen at signup must be given. A wrong one counts
 *   against the link (VERIFY_MAX_ATTEMPTS, then it locks) and does not use it,
 *   so someone who only has the inbox can't take over a signup they didn't make.
 * - email change: the change must be confirmed while signed in to that account.
 *
 * Then a signup becomes confirmed, or, if a confirmed account (e.g. Google)
 * already holds the address, merges into it. An email change moves the
 * account. Returns the user id to sign in.
 */
export async function consumeToken(
  token: string,
  proof: { password?: string; signedInUserId?: number | null }
): Promise<ConsumeResult> {
  const found = lookup(token);
  if (!found.ok) return found;
  const { info } = found;
  const db = getDb();

  if (info.purpose === 'signup') {
    const pending = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(info.userId) as { password_hash: string | null } | undefined;
    const ok = !!pending?.password_hash && !!proof.password && (await verifyPassword(proof.password, pending.password_hash));
    if (!ok) {
      const row = db
        .prepare('UPDATE verification_tokens SET failed_attempts = failed_attempts + 1 WHERE token = ? AND used_at IS NULL RETURNING failed_attempts')
        .get(hash(token)) as { failed_attempts: number } | undefined;
      return { ok: false, reason: (row?.failed_attempts ?? VERIFY_MAX_ATTEMPTS) >= VERIFY_MAX_ATTEMPTS ? 'locked' : 'wrong_password' };
    }
  } else if (proof.signedInUserId !== info.userId) {
    return { ok: false, reason: 'not_signed_in' };
  }

  return db.transaction((): ConsumeResult => {
    // Claim the token; fails if a parallel request used or locked it first
    const claimed = db
      .prepare('UPDATE verification_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL AND failed_attempts < ?')
      .run(Date.now(), hash(token), VERIFY_MAX_ATTEMPTS).changes;
    if (claimed === 0) return { ok: false, reason: 'used' };

    const confirmedHolder = db
      .prepare('SELECT id, password_hash FROM users WHERE email = ? AND email_verified IS NOT NULL AND id != ?')
      .get(info.email, info.userId) as { id: number; password_hash: string | null } | undefined;

    if (info.purpose === 'email-change') {
      if (confirmedHolder) return { ok: false, reason: 'taken' };
      db.prepare('UPDATE users SET email = ?, email_verified = ? WHERE id = ?').run(info.email, Date.now(), info.userId);
      return { ok: true, purpose: info.purpose, email: info.email, userId: info.userId, merged: false };
    }

    if (confirmedHolder) {
      // Merge into the confirmed (e.g. Google) account. The person here has
      // proved both the inbox and the signup password, so that password is
      // carried over if the account had none. The signup row goes away.
      if (!confirmedHolder.password_hash) {
        db.prepare('UPDATE users SET password_hash = (SELECT password_hash FROM users WHERE id = ?) WHERE id = ?').run(info.userId, confirmedHolder.id);
      }
      db.prepare('DELETE FROM users WHERE id = ?').run(info.userId);
      return { ok: true, purpose: info.purpose, email: info.email, userId: confirmedHolder.id, merged: true };
    }

    db.prepare('UPDATE users SET email_verified = ? WHERE id = ?').run(Date.now(), info.userId);
    return { ok: true, purpose: info.purpose, email: info.email, userId: info.userId, merged: false };
  })();
}

/** The address an email change is waiting on, if any */
export function pendingEmailChange(userId: number): string | null {
  const row = getDb()
    .prepare('SELECT identifier FROM verification_tokens WHERE identifier LIKE ? AND used_at IS NULL AND expires > ? ORDER BY expires DESC')
    .get(`email-change:${userId}:%`, Date.now()) as { identifier: string } | undefined;
  return row ? row.identifier.split(':').slice(2).join(':') : null;
}

/**
 * Makes a link (always on MAIL_LINK_BASE) and sends it through Resend.
 * Without RESEND_API_KEY the link goes to the server log, which the caller
 * reports to the user. Throws if Resend is set up but refuses the message.
 */
export async function sendVerification(purpose: VerificationPurpose, user: { id: number; name: string }, email: string): Promise<Delivery> {
  const link = `${mailLinkBase()}/verify-email?token=${createToken(purpose, user.id, email)}`;
  const message = verificationEmail({
    to: email,
    name: user.name,
    link,
    hours: RETENTION.verificationLinkHours,
    purpose,
    logoUrl: mailLogoUrl(),
  });

  if (!mailConfigured()) {
    console.warn(`[verification] RESEND_API_KEY is not set, so no email was sent. Link for ${email} (${purpose}): ${link}`);
    return 'console';
  }
  await sendMail(message);
  return 'email';
}
