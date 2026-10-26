import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildBrandIndex, detectLookalike, isOneEdit, type LookalikeKind } from '../src/lib/lookalike/detect';
import { scriptInfo, skeleton } from '../src/lib/lookalike/skeleton';
import { parseRanking } from '../src/lib/lookalike/ranking';

// A hand-made ranking (not real Tranco data): the ranks only need to put each
// domain in the right tier (top 1k, 10k, 100k)
const RANKING = parseRanking(readFileSync(new URL('./fixtures/tranco/ranking.csv', import.meta.url), 'utf8'));
const INDEX = buildBrandIndex(RANKING);

const strongest = (host: string): LookalikeKind | null => detectLookalike(host, INDEX).matches[0]?.kind ?? null;

describe('skeleton', () => {
  it('folds digits, Cyrillic and rn onto the Latin brand', () => {
    expect(skeleton('g00gle')).toBe(skeleton('google'));
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
    expect(skeleton('аpple')).toBe(skeleton('apple')); // Cyrillic а
    expect(skeleton('googlé')).toBe(skeleton('google')); // é
    expect(skeleton('applebees')).not.toBe(skeleton('apple'));
  });

  it('reports mixed scripts with the odd characters, and allows CJK mixes', () => {
    const info = scriptInfo('аpple');
    expect(info.mixed).toBe(true);
    expect(info.odd).toEqual([{ char: 'а', codePoint: 'U+0430', script: 'Cyrillic' }]);
    expect(scriptInfo('президент')).toMatchObject({ mixed: false, wholeScript: 'Cyrillic' });
    expect(scriptInfo('google-2024')).toMatchObject({ mixed: false, wholeScript: null });
    expect(scriptInfo('sonyストア').mixed).toBe(false); // Latin + Katakana
  });
});

describe('isOneEdit', () => {
  it.each([
    ['microsofft', 'microsoft', true],
    ['micorsoft', 'microsoft', true],
    ['mircosoft', 'microsoft', true],
    ['googie', 'google', true],
    ['google', 'google', false],
    ['gogle', 'google', true],
    ['gooogle', 'google', true],
    ['goolge', 'google', true],
    ['googlexx', 'google', false],
  ])('%s vs %s', (a, b, expected) => expect(isOneEdit(a, b)).toBe(expected));
});

describe('must not be flagged', () => {
  it.each([
    // The genuine article, including on ccTLDs and multi-part suffixes
    'google.com', 'microsoft.com', 'apple.com', 'paypal.com', 'www.google.com', 'mail.google.com',
    'google.co.uk', 'amazon.de', 'amazon.co.jp', 'bbc.co.uk', 'abc.net.au',
    // Brand plus a word, owned by the brand
    'googleapis.com', 'microsoftonline.com', 'paypalobjects.com', 'login.microsoftonline.com',
    // Dictionary-word and short brands
    'applebees.com', 'booking.com', 'target.com', 'x.com', 'box.com', 'zoom.us',
    // One letter apart, but both popular
    'king.com', 'bing.com',
    // Whole-script Cyrillic under a Cyrillic TLD
    'xn--d1abbgf6aiiy.xn--p1ai', 'президент.рф',
  ])('%s', (host) => {
    const report = detectLookalike(host, INDEX);
    expect(report.matches).toEqual([]);
    expect(report.mixedScript).toEqual([]);
    expect(report.rank).not.toBeNull();
  });

  it.each([
    'example.com', 'applebeesgrill.com', 'kingdom.com', 'my-login-help.com', 'targeted-ads.org',
    'gov.uk', '192.0.2.1',
    // Tenants on hosting platforms are judged by their own name
    'alice.github.io', 'myshop.blogspot.com', 'my-portfolio.vercel.app',
  ])('%s (not in the list)', (host) => {
    expect(detectLookalike(host, INDEX).matches).toEqual([]);
  });

  it('allows a whole-script Cyrillic look-alike under .ru, and says why', () => {
    const report = detectLookalike('аррӏе.ru', INDEX); // аррӏе
    expect(report.matches).toEqual([]);
    expect(report.scriptExempt).toMatch(/Cyrillic/);
  });
});

describe('must fail', () => {
  it.each<[string, LookalikeKind, string]>([
    ['g00gle.com', 'confusable', 'google.com'],
    ['paypa1.com', 'confusable', 'paypal.com'],
    ['rnicrosoft.com', 'confusable', 'microsoft.com'],
    ['xn--pple-43d.com', 'confusable', 'apple.com'],
    ['gооgle.com', 'confusable', 'google.com'], // Cyrillic о о
    ['аррӏе.com', 'confusable', 'apple.com'], // all-Cyrillic аррӏе under .com
    ['microsoft-support.co', 'credential-combo', 'microsoft.com'],
    ['secure-apple-login.net', 'credential-combo', 'apple.com'],
    ['amaz0n-billing.com', 'credential-combo', 'amazon.com'],
    ['paypallogin.com', 'credential-combo', 'paypal.com'],
    ['netflix-account-update.top', 'credential-combo', 'netflix.com'],
    ['google.com.verify-account.ru', 'embedding', 'google.com'],
    ['paypal.com-login.info', 'embedding', 'paypal.com'],
    ['login.microsoftonline.com.example-auth.net', 'embedding', 'microsoftonline.com'],
    ['www.apple.com.id-confirm.xyz', 'embedding', 'apple.com'],
    ['login-mircosoft.com', 'credential-combo', 'microsoft.com'],
    // On a hosting platform, the platform's rank doesn't vouch for the tenant
    ['paypal-login.blogspot.com', 'credential-combo', 'paypal.com'],
    ['netflix-account.github.io', 'credential-combo', 'netflix.com'],
  ])('%s → %s of %s', (host, kind, target) => {
    const report = detectLookalike(host, INDEX);
    expect(report.matches[0]).toMatchObject({ kind, target });
  });

  it('decodes punycode and flags the mixed-script label', () => {
    const report = detectLookalike('xn--pple-43d.com', INDEX);
    expect(report.unicode).toBe('аpple.com');
    expect(report.mixedScript).toHaveLength(1);
    expect(report.mixedScript[0].info.odd[0]).toMatchObject({ codePoint: 'U+0430', script: 'Cyrillic' });
  });

  it('does not treat a brand on its own ccTLD as embedding', () => {
    expect(strongest('accounts.google.com.au')).toBe('tld-swap');
  });
});

describe('should warn, not fail', () => {
  it.each<[string, LookalikeKind]>([
    ['microsofft.com', 'edit-distance'],
    ['amazom.com', 'edit-distance'],
    ['paypal.zip', 'tld-swap'],
    ['amazon-deals-today.com', 'brand-word'],
  ])('%s → %s', (host, kind) => expect(strongest(host)).toBe(kind));

  it('skips edit distance for short names and first-letter swaps', () => {
    expect(strongest('xbox.com')).toBeNull(); // "x" is too short to have typos
    expect(strongest('cooking.com')).toBeNull(); // booking: only the first letter differs
    expect(strongest('google1.com')).toBeNull(); // trailing digit
    expect(strongest('goo-gle.com')).toBeNull(); // hyphen only
  });
});

describe('ranking parser', () => {
  it('reads rank,domain lines and skips junk', () => {
    expect(parseRanking('1,google.com\r\n2,Example.ORG\n\nbad line\n3,\n')).toEqual([
      { rank: 1, domain: 'google.com' },
      { rank: 2, domain: 'example.org' },
    ]);
  });
});

describe('hosting platforms and suffix swaps', () => {
  it('names the platform a tenant is on', () => {
    expect(detectLookalike('paypal-login.blogspot.com', INDEX)).toMatchObject({ registrable: 'paypal-login.blogspot.com', platform: 'blogspot.com', rank: null });
    expect(detectLookalike('blogspot.com', INDEX)).toMatchObject({ registrable: 'blogspot.com', platform: null, rank: 90 });
  });

  it('marks country-code swaps, which brands often own', () => {
    expect(detectLookalike('paypal.ca', INDEX).matches[0]).toMatchObject({ kind: 'tld-swap', countryCode: true });
    expect(detectLookalike('paypal.zip', INDEX).matches[0]).toMatchObject({ kind: 'tld-swap', countryCode: false });
    expect(detectLookalike('paypal.vercel.app', INDEX).matches[0]).toMatchObject({ kind: 'tld-swap', countryCode: false, why: 'same name as paypal.com on vercel.app' });
  });

  it('protects common-word brands only near the top, and never by typo or run-together name below 100', () => {
    expect(strongest('target-login.com')).toBe('credential-combo'); // target: common word, rank 600
    expect(strongest('targetlogin.com')).toBeNull(); // run together: needs a top-100 brand
    expect(strongest('applelogin.com')).toBe('credential-combo'); // apple: rank 12
    expect(strongest('kingdom-login.com')).toBeNull(); // king: common word, rank 5400
  });
});
