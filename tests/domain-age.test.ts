import { describe, expect, it } from 'vitest';
import { domainAgeFindings, registrationUnavailable } from '../src/lib/server/analysis/domain-age';
import { calculateRiskScore } from '../src/lib/server/analysis/scoring';
import type { DomainRegistration } from '../src/lib/rdap';

const base: DomainRegistration = {
  createdAt: '2010-01-01T00:00:00.000Z',
  updatedAt: null,
  expiresAt: '2030-01-01T00:00:00.000Z',
  ageDays: 6000,
  registrar: 'Example Registrar',
  status: [],
  nameservers: [],
  source: 'rdap',
};
const reg = (over: Partial<DomainRegistration>) => ({ ...base, ...over });
const byId = (r: DomainRegistration, id: string) => domainAgeFindings(r).find((f) => f.id === id);

describe('domain age', () => {
  it('under 30 days: high-risk warning (25 points)', () => {
    const f = byId(reg({ ageDays: 12 }), 'domain-age');
    expect(f).toMatchObject({ status: 'warning', severity: 'high' });
    expect(calculateRiskScore([f!])).toBe(25);
  });

  it('30 to 179 days: medium warning (15 points)', () => {
    expect(byId(reg({ ageDays: 30 }), 'domain-age')).toMatchObject({ status: 'warning', severity: 'medium' });
    expect(byId(reg({ ageDays: 179 }), 'domain-age')).toMatchObject({ status: 'warning', severity: 'medium' });
  });

  it('180 days and older: pass, no points', () => {
    const f = byId(reg({ ageDays: 180 }), 'domain-age');
    expect(f?.status).toBe('pass');
    expect(calculateRiskScore([f!])).toBe(0);
  });

  it('no registration date: unknown, never scored', () => {
    const f = byId(reg({ ageDays: null, createdAt: null }), 'domain-age');
    expect(f?.status).toBe('unknown');
    expect(calculateRiskScore([f!])).toBe(0);
  });

  it('all lookups failed: a skipped row that adds nothing', () => {
    const f = registrationUnavailable();
    expect(f.status).toBe('unknown');
    expect(calculateRiskScore([f])).toBe(0);
  });
});

describe('registry hold', () => {
  it.each(['client hold', 'server hold'])('"%s" is flagged', (status) => {
    expect(byId(reg({ status: ['client transfer prohibited', status] }), 'domain-hold')).toMatchObject({ status: 'warning', severity: 'medium' });
  });

  it('other statuses are not', () => {
    expect(byId(reg({ status: ['server transfer prohibited', 'client delete prohibited'] }), 'domain-hold')).toBeUndefined();
  });
});

describe('registration term', () => {
  it('expiring within a year of creation is a mild flag (5 points)', () => {
    const f = byId(reg({ createdAt: '2026-10-01T00:00:00.000Z', expiresAt: '2027-10-01T00:00:00.000Z', ageDays: 22 }), 'domain-short-term');
    expect(f).toMatchObject({ status: 'warning', severity: 'low' });
    expect(calculateRiskScore([f!])).toBe(5);
  });

  it('longer registrations are not flagged', () => {
    expect(byId(reg({ createdAt: '2026-10-01T00:00:00.000Z', expiresAt: '2028-10-01T00:00:00.000Z' }), 'domain-short-term')).toBeUndefined();
  });
});
