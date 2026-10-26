import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { Indicator } from '../src/types';
import { PATTERN_ONLY_NOTE, scoreFindings } from '../src/lib/server/analysis/scoring';
import { lookalikeFindings } from '../src/lib/server/analysis/lookalike';
import { buildBrandIndex, detectLookalike } from '../src/lib/lookalike/detect';
import { parseRanking } from '../src/lib/lookalike/ranking';
import { riskLevelFor, UNCORROBORATED_CAP } from '../src/lib/scoring-rules';

const INDEX = buildBrandIndex(parseRanking(readFileSync(new URL('./fixtures/tranco/ranking.csv', import.meta.url), 'utf8')));
const LIST = { listId: 'TEST1', startDate: '2026-09-23', endDate: '2026-10-22', providers: [], rows: 28, createdOn: null };
const INDEPENDENT = ['virustotal', 'safe-browsing', 'openphish', 'blocklist-coverage', 'abuse-reports', 'ip-blacklists'];
const independent = (i: Indicator) => INDEPENDENT.includes(i.id);

const finding = (id: string, status: Indicator['status'], severity: Indicator['severity']): Indicator => ({
  id, name: id, status, severity, description: '', source: 'test',
});
const youngDomain = finding('domain-age', 'warning', 'high');
const suspiciousTld = finding('suspicious-tld', 'warning', 'medium');

describe('corroboration cap', () => {
  it('caps pattern-only findings at Medium', () => {
    const indicators = [...lookalikeFindings(detectLookalike('paypa1.com', INDEX), LIST), youngDomain, suspiciousTld];
    const result = scoreFindings(indicators, { independent });
    expect(result).toEqual({ score: UNCORROBORATED_CAP, patternOnly: true, capped: true });
    expect(riskLevelFor(result.score)).toBe('medium');
  });

  it('lets an independent source lift it to High or Critical', () => {
    const indicators = [...lookalikeFindings(detectLookalike('paypa1.com', INDEX), LIST), youngDomain, finding('openphish', 'fail', 'critical')];
    const result = scoreFindings(indicators, { independent });
    expect(result.patternOnly).toBe(false);
    expect(riskLevelFor(result.score)).toBe('critical');
  });

  it('does not count a source that answered clean', () => {
    const indicators = [...lookalikeFindings(detectLookalike('g00gle.com', INDEX), LIST), youngDomain, finding('virustotal', 'pass', 'low')];
    expect(scoreFindings(indicators, { independent }).score).toBe(UNCORROBORATED_CAP);
  });

  it('only applies when the analyzer asks for it', () => {
    expect(scoreFindings([finding('x', 'fail', 'critical')]).score).toBe(60);
  });

  it('the genuine article adds nothing (the google.com case)', () => {
    const indicators = [...lookalikeFindings(detectLookalike('google.com', INDEX), LIST), finding('virustotal', 'warning', 'high')];
    expect(indicators[0]).toMatchObject({ id: 'lookalike', status: 'pass' });
    expect(scoreFindings(indicators, { independent }).score).toBe(25);
  });

  it('has the note for the summary', () => {
    expect(PATTERN_ONLY_NOTE).toBe('Flagged by pattern rules only; no source has reported it.');
  });
});

describe('look-alike findings', () => {
  it('shows the decoded form and the odd characters of a punycode look-alike', () => {
    const [main, mixed] = lookalikeFindings(detectLookalike('xn--pple-43d.com', INDEX), LIST);
    expect(main).toMatchObject({ id: 'lookalike', status: 'fail', severity: 'critical' });
    expect(main.description).toBe('Imitates apple.com (rank 12): аpple.com (xn--pple-43d.com) renders like apple.com; Cyrillic "а" (U+0430).');
    expect(mixed).toMatchObject({ id: 'mixed-script', status: 'warning', severity: 'medium' });
    expect(mixed.description).toContain('"аpple" (xn--pple-43d) mixes Latin and Cyrillic: Cyrillic "а" (U+0430)');
  });

  it('grades each kind', () => {
    const grade = (host: string) => {
      const [f] = lookalikeFindings(detectLookalike(host, INDEX), LIST);
      return `${f.status}/${f.severity}`;
    };
    expect(grade('google.com.verify-account.ru')).toBe('fail/critical');
    expect(grade('microsoft-support.co')).toBe('fail/critical');
    expect(grade('microsofft.com')).toBe('warning/high');
    expect(grade('paypal.zip')).toBe('warning/medium');
    expect(grade('paypal.ca')).toBe('warning/low');
    expect(grade('amazon-deals-today.com')).toBe('warning/low');
    expect(grade('example.com')).toBe('pass/low');
  });

  it('says when a site is on a hosting platform', () => {
    const [f] = lookalikeFindings(detectLookalike('paypal-login.blogspot.com', INDEX), LIST);
    expect(f.description).toContain('It is a site on blogspot.com, where anyone can publish.');
  });
});
