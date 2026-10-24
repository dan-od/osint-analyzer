// Findings from a domain's registration data (src/lib/rdap.ts):
// - registered < 30 days ago: Warn, high
// - registered < 180 days ago: Warn, medium
// - "client hold" / "server hold" status: Warn, medium
// - expires within a year of registration: Warn, low
// No registration data at all is not scored (the task reports it as skipped).
// Type-only imports, so the tests can load this file directly.
import type { AnalysisDetail, Indicator } from '@/types';
import type { DomainRegistration } from '../../rdap';

const DAY_MS = 24 * 60 * 60 * 1000;
export const NEW_DOMAIN_DAYS = 30;
export const RECENT_DOMAIN_DAYS = 180;
const HOLD_STATUSES = ['client hold', 'server hold'];

const sourceLabel = (reg: DomainRegistration) => (reg.source === 'rdap' ? 'RDAP' : 'WHOIS');

export function domainAgeFindings(reg: DomainRegistration): Indicator[] {
  const source = sourceLabel(reg);
  const days = reg.ageDays;
  const findings: Indicator[] = [];

  if (days === null) {
    findings.push({ id: 'domain-age', name: 'Domain age', status: 'unknown', severity: 'low', description: 'Registration date not published.', source });
  } else if (days < NEW_DOMAIN_DAYS) {
    findings.push({
      id: 'domain-age',
      name: 'Domain age',
      status: 'warning',
      severity: 'high',
      description: `Registered ${days} day${days === 1 ? '' : 's'} ago. Brand-new domains are common in scams.`,
      source,
    });
  } else if (days < RECENT_DOMAIN_DAYS) {
    findings.push({
      id: 'domain-age',
      name: 'Domain age',
      status: 'warning',
      severity: 'medium',
      description: `Registered ${days} days ago, under six months.`,
      source,
    });
  } else {
    const years = Math.floor(days / 365);
    findings.push({
      id: 'domain-age',
      name: 'Domain age',
      status: 'pass',
      severity: 'low',
      description: `Registered ${days.toLocaleString('en-US')} days ago${years ? ` (about ${years} year${years === 1 ? '' : 's'})` : ''}. Not a throwaway domain.`,
      source,
    });
  }

  const holds = reg.status.filter((s) => HOLD_STATUSES.includes(s));
  if (holds.length > 0) {
    findings.push({
      id: 'domain-hold',
      name: 'Registry hold',
      status: 'warning',
      severity: 'medium',
      description: `Status "${holds.join('", "')}": the registry or registrar has suspended this domain, often for abuse or non-payment.`,
      source,
    });
  }

  if (reg.createdAt && reg.expiresAt) {
    const term = Date.parse(reg.expiresAt) - Date.parse(reg.createdAt);
    if (term > 0 && term <= 366 * DAY_MS) {
      findings.push({
        id: 'domain-short-term',
        name: 'Registration term',
        status: 'warning',
        severity: 'low',
        description: `Registered for a year or less (expires ${reg.expiresAt.slice(0, 10)}). Throwaway domains are rarely paid for longer.`,
        source,
      });
    }
  }

  return findings;
}

/** The raw-data panel for a domain's registration */
export function registrationDetail(domain: string, reg: DomainRegistration): AnalysisDetail {
  const flagged = domainAgeFindings(reg).some((f) => f.status === 'warning' || f.status === 'fail');
  return {
    title: `Registration (${sourceLabel(reg)}), ${domain}`,
    data: {
      registrar: reg.registrar || 'unknown',
      created: reg.createdAt?.slice(0, 10) || 'unknown',
      expires: reg.expiresAt?.slice(0, 10) || 'unknown',
      updated: reg.updatedAt?.slice(0, 10) || 'unknown',
      age: reg.ageDays !== null ? `${reg.ageDays} days` : 'unknown',
      status: reg.status.join(', ') || 'none',
      nameservers: reg.nameservers.join(', ') || 'none',
    },
    status: flagged ? 'warning' : 'pass',
  };
}

/** Shown when RDAP, rdap.org and WHOIS all came back empty: skipped, never scored */
export function registrationUnavailable(): Indicator {
  return {
    id: 'skipped-whois',
    name: 'Domain age',
    status: 'unknown',
    severity: 'low',
    description: 'No registration data: RDAP and WHOIS gave no answer. Not counted in the score.',
    source: 'RDAP',
  };
}
