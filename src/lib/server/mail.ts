// Outgoing email through the Resend HTTP API (RESEND_API_KEY). Without a key
// nothing is sent: callers write the link to the server log and say so in the
// UI. Messages are transactional, so there is no List-Unsubscribe header.
// Links in emails come from MAIL_LINK_BASE, never from the request's host.

export const MAIL_FROM = 'OSINT Analyzer <osint@protechnetworks.org>';
export const MAIL_REPLY_TO = 'support@protechnetworks.org';

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

export interface InlineImage {
  filename: string;
  contentBase64: string;
  /** Referenced from the HTML as src="cid:<contentId>" */
  contentId: string;
}

export interface MailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
  inline?: InlineImage[];
}

export async function sendMail(message: MailMessage): Promise<void> {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY!.trim()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: MAIL_FROM,
      to: [message.to],
      reply_to: MAIL_REPLY_TO,
      subject: message.subject,
      html: message.html,
      text: message.text,
      attachments: (message.inline ?? []).map((img) => ({
        filename: img.filename,
        content: img.contentBase64,
        content_id: img.contentId,
      })),
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    const body = (await response.text().catch(() => '')).slice(0, 500);
    throw new Error(`Resend ${response.status}: ${body}`);
  }
}
