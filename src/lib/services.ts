// Catalog of services that accept a per-user API key. Shared by the server
// (key resolution, quotas) and the Settings page (descriptions, links).
// Links and limits were checked on the providers' own pages in Oct 2026.

export type ServiceId =
  | 'virustotal'
  | 'abuseipdb'
  | 'ipqs'
  | 'hunter'
  | 'greynoise'
  | 'hibp'
  | 'otx'
  | 'abusech'
  | 'spamhaus_dqs';

export interface ServiceQuota {
  limit: number;
  /** 'week' is a rolling 7 days */
  period: 'day' | 'week' | 'month';
  /** Extra per-day cap inside a weekly/monthly allowance */
  dailyCap?: number;
}

export interface ServiceInfo {
  id: ServiceId;
  name: string;
  description: string;
  freeTier: string;
  signupUrl: string;
  apiKeyUrl: string;
  /** Server-wide fallback key */
  envVar: string;
  /** Free-tier quota we track per user, when the provider publishes one */
  quota: ServiceQuota | null;
  /** Provider's per-minute cap for the free tier */
  perMinute: number | null;
  keyPattern: RegExp;
  keyHint: string;
}

const GENERIC_KEY = /^[A-Za-z0-9._-]{16,200}$/;

export const SERVICES: ServiceInfo[] = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'Domains and IPs. Verdicts from 90+ security engines.',
    freeTier: '500 lookups a day, 4 a minute. Non-commercial use only.',
    signupUrl: 'https://www.virustotal.com/gui/join-us',
    apiKeyUrl: 'https://www.virustotal.com/gui/my-apikey',
    envVar: 'VIRUSTOTAL_API_KEY',
    quota: { limit: 500, period: 'day' },
    perMinute: 4,
    keyPattern: GENERIC_KEY,
    keyHint: '64-character hex key',
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'IP abuse reports and confidence score.',
    freeTier: '1,000 checks a day.',
    signupUrl: 'https://www.abuseipdb.com/register',
    apiKeyUrl: 'https://www.abuseipdb.com/account/api',
    envVar: 'ABUSEIPDB_API_KEY',
    quota: { limit: 1000, period: 'day' },
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: '80-character hex key',
  },
  {
    id: 'ipqs',
    name: 'IPQualityScore',
    description: 'Email and phone fraud scoring.',
    freeTier: '1,000 a month with a 35-a-day cap, shared across email and phone.',
    signupUrl: 'https://www.ipqualityscore.com/create-account',
    apiKeyUrl: 'https://www.ipqualityscore.com/user/settings',
    envVar: 'IPQUALITYSCORE_API_KEY',
    quota: { limit: 1000, period: 'month', dailyCap: 35 },
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: '32-character key',
  },
  {
    id: 'hunter',
    name: 'Hunter.io',
    description: 'Email deliverability: does the mailbox exist and accept mail?',
    freeTier: '50 credits a month; a verification costs 0.5, so about 100 checks.',
    signupUrl: 'https://hunter.io/users/sign_up',
    apiKeyUrl: 'https://hunter.io/api-keys',
    envVar: 'HUNTER_API_KEY',
    quota: { limit: 100, period: 'month' },
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: '40-character key',
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'Is this IP a mass scanner or targeted? IPv4 only.',
    freeTier: '50 lookups a week. Keys are only issued to accounts registered with a business email.',
    signupUrl: 'https://viz.greynoise.io/signup',
    apiKeyUrl: 'https://viz.greynoise.io/workspace#api-key',
    envVar: 'GREYNOISE_API_KEY',
    quota: { limit: 50, period: 'week' },
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: 'Community API key',
  },
  {
    id: 'hibp',
    name: 'Have I Been Pwned',
    description: 'Breach history for an email address.',
    freeTier: 'Paid key, from about 4.39 USD a month (10 lookups a minute). Optional.',
    signupUrl: 'https://haveibeenpwned.com/Subscription',
    apiKeyUrl: 'https://haveibeenpwned.com/API/Key',
    envVar: 'HIBP_API_KEY',
    quota: null,
    perMinute: 10,
    keyPattern: GENERIC_KEY,
    keyHint: '32-character hex key',
  },
  {
    id: 'otx',
    name: 'AlienVault OTX',
    description: 'Community threat pulses for domains and IPs.',
    freeTier: 'Free, no published quota.',
    signupUrl: 'https://otx.alienvault.com/#signup',
    apiKeyUrl: 'https://otx.alienvault.com/api',
    envVar: 'OTX_API_KEY',
    quota: null,
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: '64-character hex key (OTX Key)',
  },
  {
    id: 'abusech',
    name: 'abuse.ch',
    description: 'URLhaus and ThreatFox: malware URLs, C2 servers and other IOCs.',
    freeTier: 'Free. One Auth-Key covers both; sign in with GitHub, Google, LinkedIn or X, then generate it under "Optional".',
    signupUrl: 'https://auth.abuse.ch/',
    apiKeyUrl: 'https://auth.abuse.ch/',
    envVar: 'ABUSECH_AUTH_KEY',
    quota: null,
    perMinute: null,
    keyPattern: GENERIC_KEY,
    keyHint: 'abuse.ch Auth-Key',
  },
  {
    id: 'spamhaus_dqs',
    name: 'Spamhaus DQS',
    description: 'Reliable DNS blocklist answers.',
    freeTier: 'Free for non-commercial use, up to 100,000 queries a day. Without it, Spamhaus checks fall back to the public mirror.',
    signupUrl: 'https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product',
    apiKeyUrl: 'https://portal.spamhaus.com/dqs',
    envVar: 'SPAMHAUS_DQS_KEY',
    quota: { limit: 100_000, period: 'day' },
    perMinute: null,
    // Becomes part of a DNS name, so only letters and digits
    keyPattern: /^[A-Za-z0-9]{16,64}$/,
    keyHint: 'letters and digits only',
  },
];

export const SERVICE_IDS = SERVICES.map((s) => s.id);

export function getService(id: string): ServiceInfo | undefined {
  return SERVICES.find((s) => s.id === id);
}

export function maskKey(last4: string): string {
  return `••••••••${last4}`;
}
