// Outgoing email through the Resend HTTP API (RESEND_API_KEY). Without a key
// nothing is sent: callers write the link to the server log and say so in the
// UI. Messages are transactional, so there is no List-Unsubscribe header.
// Links in emails come from MAIL_LINK_BASE, never from the request's host.
// Sender and reply-to come from MAIL_FROM and MAIL_REPLY_TO, so a new sending
// domain is a config change, not a code change.

const DEFAULT_FROM = 'OSINT Analyzer <osint@mail.protechnetworks.org>';
const DEFAULT_REPLY_TO = 'support@protechnetworks.org';

/** The From header, e.g. "OSINT Analyzer <osint@mail.protechnetworks.org>" */
export function mailFrom(): string {
  return process.env.MAIL_FROM?.trim() || DEFAULT_FROM;
}

export function mailReplyTo(): string {
  return process.env.MAIL_REPLY_TO?.trim() || DEFAULT_REPLY_TO;
}

/** Just the address part of the From header (for the privacy policy) */
export function mailFromAddress(): string {
  const from = mailFrom();
  return from.match(/<([^>]+)>/)?.[1] ?? from;
}

export function mailConfigured(): boolean {
  return !!process.env.RESEND_API_KEY?.trim();
}

let warnedBase = false;

/** Base URL for links in emails: MAIL_LINK_BASE (prod https://osint.okoro.me, dev http://localhost:3000) */
export function mailLinkBase(): string {
  const base = process.env.MAIL_LINK_BASE?.trim();
  if (base) return base.replace(/\/+$/, '');
  if (!warnedBase) {
    console.warn('[mail] MAIL_LINK_BASE is not set; email links use http://localhost:3000');
    warnedBase = true;
  }
  return 'http://localhost:3000';
}

export interface MailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
}

/** The email logo, served from public/email-logo.png */
export function mailLogoUrl(): string {
  return `${mailLinkBase()}/email-logo.png`;
}

export async function sendMail(message: MailMessage): Promise<void> {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY!.trim()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: mailFrom(),
      to: [message.to],
      reply_to: mailReplyTo(),
      subject: message.subject,
      html: message.html,
      text: message.text,
      // No attachments: images are remote (see email/verification-email.ts)
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    const body = (await response.text().catch(() => '')).slice(0, 500);
    throw new Error(`Resend ${response.status}: ${body}`);
  }
}
