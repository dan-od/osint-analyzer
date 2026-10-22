// The confirmation email: a dark card like the site, the sweep logo inline
// (CID), one orange button, and a plain-text part with the same content.
import { LOGO_CID, LOGO_PNG_BASE64 } from './logo';
import type { MailMessage } from '../mail';

export const VERIFICATION_SUBJECT = 'Confirm your email for OSINT Analyzer';

const escape = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const MONO = "'SFMono-Regular',Menlo,Consolas,monospace";

export function verificationEmail(opts: {
  to: string;
  name: string;
  link: string;
  hours: number;
  purpose: 'signup' | 'email-change';
}): MailMessage {
  const { to, name, link, hours, purpose } = opts;
  const lead =
    purpose === 'signup'
      ? 'Confirm your email address to finish creating your OSINT Analyzer account. You will be asked for the password you chose when you signed up.'
      : `Confirm ${to} as the new email address for your OSINT Analyzer account. You will need to be logged in to it.`;
  const ignore =
    purpose === 'signup'
      ? "If you didn't sign up, ignore this email. Nobody can use your address without the password chosen at signup."
      : "If you didn't ask for this, ignore this email and nothing will change.";

  const text = [
    `Hi ${name},`,
    '',
    lead,
    '',
    link,
    '',
    `The link works once and expires in ${hours} hours.`,
    ignore,
    '',
    'OSINT Analyzer · https://osint.okoro.me',
  ].join('\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${escape(VERIFICATION_SUBJECT)}</title></head>
<body style="margin:0;padding:0;background:#15181C;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#15181C;">
<tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:480px;background:#1A1E23;border:1px solid #2C3238;border-radius:4px;">
    <tr><td style="padding:28px 32px 0;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="vertical-align:middle;"><img src="cid:${LOGO_CID}" width="40" height="40" alt="" style="display:block;border:0;border-radius:3px;"></td>
        <td style="vertical-align:middle;padding-left:12px;font-family:${FONT};font-size:16px;font-weight:600;color:#E6E9EC;">OSINT Analyzer</td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:24px 32px 8px;font-family:${FONT};">
      <h1 style="margin:0 0 12px;font-size:22px;line-height:1.25;font-weight:700;color:#FFFFFF;">Confirm your email</h1>
      <p style="margin:0 0 6px;font-size:15px;line-height:1.55;color:#C9D0D6;">Hi ${escape(name)},</p>
      <p style="margin:0;font-size:15px;line-height:1.55;color:#C9D0D6;">${escape(lead)}</p>
    </td></tr>
    <tr><td style="padding:20px 32px 4px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td bgcolor="#F28C28" style="border-radius:3px;">
          <a href="${escape(link)}" style="display:inline-block;padding:13px 26px;font-family:${FONT};font-size:15px;font-weight:700;color:#15181C;text-decoration:none;border-radius:3px;">Confirm email address</a>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:16px 32px 0;font-family:${FONT};">
      <p style="margin:0;font-size:13px;line-height:1.55;color:#9AA3AD;">The link works once and expires in ${hours} hours. If the button doesn't work, paste this into your browser:</p>
      <p style="margin:8px 0 0;font-family:${MONO};font-size:12px;line-height:1.5;word-break:break-all;"><a href="${escape(link)}" style="color:#8FB8F5;">${escape(link)}</a></p>
    </td></tr>
    <tr><td style="padding:20px 32px 28px;font-family:${FONT};">
      <p style="margin:0;padding-top:16px;border-top:1px solid #2C3238;font-size:12px;line-height:1.55;color:#878F99;">${escape(ignore)}</p>
    </td></tr>
  </table>
  <p style="margin:16px 0 0;font-family:${FONT};font-size:12px;color:#878F99;">OSINT Analyzer · <a href="https://osint.okoro.me" style="color:#878F99;">osint.okoro.me</a></p>
</td></tr>
</table>
</body>
</html>`;

  return {
    to,
    subject: VERIFICATION_SUBJECT,
    html,
    text,
    inline: [{ filename: 'osint-analyzer.png', contentBase64: LOGO_PNG_BASE64, contentId: LOGO_CID }],
  };
}
