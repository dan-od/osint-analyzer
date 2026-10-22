// Facts the privacy policy and terms quote. Change LEGAL_LAST_UPDATED whenever
// either page's substance changes; the pages render it, so it's never stale prose.
export const LEGAL_LAST_UPDATED = '2026-10-22';

export const OPERATOR = 'Daniel Okoro';
/** Primary contact on /privacy and /terms */
export const CONTACT_EMAIL = 'danievwe@gmail.com';
/** Alternate contact, same person */
export const ALT_CONTACT_EMAIL = 'daniel.ookoro@gmail.com';
export const SITE_URL = 'https://osint.okoro.me';
export const HOSTING = 'a server Daniel Okoro runs himself in Ontario, Canada, reached through a Cloudflare Tunnel';
export const JURISDICTION = 'the Province of Ontario and the federal laws of Canada that apply there';

export function formatLegalDate(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-CA', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
}
