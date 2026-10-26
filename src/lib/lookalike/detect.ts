// Look-alike (typosquatting / brand impersonation) detection, anchored on a
// popularity ranking instead of a hand-kept brand list. Pure: no I/O, so it
// runs against an in-memory index and costs microseconds per domain.
//
// Order of checks (see docs/proposals/lookalike-detection.md):
//   1. A domain in the top 100k is the genuine article: nothing else runs.
//   2. A top-10k domain embedded in the host (google.com.verify-account.ru): Fail
//   3. Same confusable skeleton as a top-10k brand (g00gle, Cyrillic аpple): Fail
//   4. A top-10k brand plus a credential word (microsoft-support): Fail
//   5. One edit from a top-1k brand (microsofft): Warn high
//   6. A top-10k brand's name on another suffix (paypal.zip): Warn medium
//   7. A top-10k brand plus any other word (amazon-deals): Warn low
// Separately, labels mixing scripts are reported whether or not they match.
//
// Brands whose name is a common English word ("apple", "target", "cloud")
// are only protected in the top 1k, and only in the top 100 for typos and
// run-together names: the ranking alone can't tell Apple from an orchard.
//
// Sites on hosting platforms (PSL private section: vercel.app, github.io,
// pages.dev) are judged by their own name, not the platform's rank: most
// phishing in the OpenPhish feed lives there.
import { domainToASCII, domainToUnicode } from 'url';
import { parse } from 'tldts';
import commonWords from './common-words.json';
import { scriptInfo, skeleton, type ScriptInfo } from './skeleton';

const COMMON_WORDS = new Set((commonWords as { words: string[] }).words);

export const LIMITS = {
  /** Ranks treated as the genuine article */
  known: 100_000,
  /** Ranks protected against embedding, confusables, combos and suffix swaps */
  brands: 10_000,
  /** Ranks protected against one-letter typos (noisier, so fewer) */
  editDistance: 1_000,
  /** Brands named after a common word are only protected this high up */
  commonWordBrands: 1_000,
  /** ... and against typos or run-together names only this high up ("amazom", not "cloudz") */
  commonWordTop: 100,
  /** Chrome: kMinLengthForEditDistance */
  minEditLength: 5,
  /** Chrome: embedded or combined brand names must be longer than 4 characters */
  minBrandLength: 5,
  /** Shorter names collide with too many ordinary ones ("tom" / "torn") */
  minConfusableLength: 4,
};

/** Words that turn "brand + word" into a credential-phishing pattern (Chrome, phishing_catcher, dnstwist) */
export const CREDENTIAL_WORDS = new Set([
  'login', 'logon', 'signin', 'signon', 'sso', 'auth', 'authenticate', 'authentication', '2fa', 'mfa',
  'secure', 'security', 'verify', 'verification', 'validate', 'validation', 'confirm', 'confirmation',
  'account', 'accounts', 'id', 'password', 'passwd', 'reset', 'recover', 'recovery', 'unlock', 'unlocked',
  'suspended', 'suspend', 'activate', 'activation', 'alert', 'update', 'support', 'helpdesk',
  'billing', 'invoice', 'payment', 'payments', 'refund', 'wallet', 'banking', 'webscr',
]);
/** Only long keywords are looked for inside a run-together label ("paypallogin") */
const CONCAT_WORDS = Array.from(CREDENTIAL_WORDS).filter((w) => w.length >= 5);

/** ccTLDs whose own script makes a whole-script label legitimate (TR39 5.3, Chrome idn.md) */
const SCRIPT_TLDS: Record<string, string[]> = {
  Cyrillic: ['ru', 'su', 'by', 'bg', 'kz', 'kg', 'mk', 'mn', 'rs', 'ua', 'tj', 'uz', 'me'],
  Greek: ['gr', 'cy'],
};

export interface RankedDomain {
  rank: number;
  /** Registrable domain, ASCII (punycode for IDNs) */
  domain: string;
}

interface Brand {
  rank: number;
  domain: string;
  /** The domain as people see it (IDNs decoded) */
  display: string;
  /** Registrable domain minus its public suffix ("google" for google.co.uk), decoded */
  label: string;
  /** The label is a common English word */
  common: boolean;
}

/** Common-word brands count only near the top of the ranking */
const isProtected = (brand: Brand) => !brand.common || brand.rank <= LIMITS.commonWordBrands;

export interface BrandIndex {
  size: number;
  rankOf: Map<string, number>;
  byLabel: Map<string, Brand>;
  byLabelSkeleton: Map<string, Brand>;
  byDomainSkeleton: Map<string, Brand>;
  /** Deletion neighbourhood of the top-1k labels, for edit distance 1 */
  deletions: Map<string, Brand[]>;
}

function deletes(word: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < word.length; i++) out.push(word.slice(0, i) + word.slice(i + 1));
  return out;
}

function keepBest<K>(map: Map<K, Brand>, key: K, brand: Brand) {
  const current = map.get(key);
  if (!current || brand.rank < current.rank) map.set(key, brand);
}

/** Builds the lookup tables from a ranking (rank 1 first). */
export function buildBrandIndex(ranking: RankedDomain[]): BrandIndex {
  const index: BrandIndex = {
    size: 0,
    rankOf: new Map(),
    byLabel: new Map(),
    byLabelSkeleton: new Map(),
    byDomainSkeleton: new Map(),
    deletions: new Map(),
  };
  for (const { rank, domain } of ranking) {
    if (rank > LIMITS.known) continue;
    if (!index.rankOf.has(domain)) index.rankOf.set(domain, rank);
    index.size++;
    if (rank > LIMITS.brands) continue;

    const parsed = parse(domain);
    if (!parsed.domain || !parsed.domainWithoutSuffix) continue;
    const display = domainToUnicode(domain) || domain;
    const label = domainToUnicode(parsed.domainWithoutSuffix) || parsed.domainWithoutSuffix;
    // A brand called "login" or "account" would turn every credential word into a match
    if (CREDENTIAL_WORDS.has(label)) continue;
    const brand: Brand = { rank, domain, display, label, common: COMMON_WORDS.has(label) };

    keepBest(index.byLabel, label, brand);
    keepBest(index.byDomainSkeleton, skeleton(display), brand);
    if (label.length >= LIMITS.minConfusableLength) keepBest(index.byLabelSkeleton, skeleton(label), brand);

    if (rank <= LIMITS.editDistance && (!brand.common || rank <= LIMITS.commonWordTop) && label.length >= LIMITS.minEditLength && /^[a-z0-9-]+$/.test(label)) {
      for (const key of [label, ...deletes(label)]) {
        const list = index.deletions.get(key);
        if (!list) index.deletions.set(key, [brand]);
        else if (!list.some((b) => b.label === label)) list.push(brand);
      }
    }
  }
  return index;
}

export type LookalikeKind = 'embedding' | 'confusable' | 'credential-combo' | 'edit-distance' | 'tld-swap' | 'brand-word';

export const KIND_ORDER: LookalikeKind[] = ['embedding', 'confusable', 'credential-combo', 'edit-distance', 'tld-swap', 'brand-word'];

export interface LookalikeMatch {
  kind: LookalikeKind;
  /** The popular domain it imitates */
  target: string;
  targetRank: number;
  /** Plain-words reason, e.g. 'contains "google.com" before its real domain' */
  why: string;
  /** A tld-swap onto a country-code TLD: brands often hold those without ranking there */
  countryCode?: boolean;
}

export interface LookalikeReport {
  /** Lower-case ASCII host (punycode) */
  ascii: string;
  /** The host as it renders (xn-- labels decoded) */
  unicode: string;
  /** Registrable domain, ASCII; null for an IP, a bare suffix or junk. On a hosting platform, the tenant's site */
  registrable: string | null;
  /** The registrable domain minus its suffix, decoded ("аpple" for xn--pple-43d.com) */
  label: string | null;
  /** The hosting platform (vercel.app, github.io) when the host is one of its tenants */
  platform: string | null;
  /** Popularity rank of the registrable domain when it is in the list */
  rank: number | null;
  matches: LookalikeMatch[];
  /** Labels that mix scripts, decoded, with the odd characters */
  mixedScript: { label: string; info: ScriptInfo }[];
  /** A whole-script non-Latin label that skeleton-matches a brand, allowed by its ccTLD */
  scriptExempt: string | null;
}

/** Optimal string alignment distance is exactly 1 (insert, delete, substitute or swap neighbours) */
export function isOneEdit(a: string, b: string): boolean {
  if (a === b) return false;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  let i = 0;
  while (i < Math.min(la, lb) && a[i] === b[i]) i++;
  if (la === lb) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true; // substitution
    return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2); // transposition
  }
  return la > lb ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}

/** Chrome's IsLikelyEditDistanceFalsePositive, roughly */
function likelyFalsePositive(a: string, b: string): boolean {
  // Only the first letter differs, or one is added in front: "hank" / "tank", "qcloud" / "cloud"
  if (a.length === b.length && a.slice(1) === b.slice(1)) return true;
  if (a.slice(1) === b || b.slice(1) === a) return true;
  // Only trailing digits differ: "example1" / "example2"
  const stripA = a.replace(/\d+$/, '');
  if (stripA !== a && stripA === b.replace(/\d+$/, '')) return true;
  if (stripA === b || a === b.replace(/\d+$/, '')) return true;
  // Only a hyphen added or removed: "goo-gle"
  return a.replace(/-/g, '') === b.replace(/-/g, '');
}

function editDistanceMatch(label: string, index: BrandIndex): Brand | null {
  if (label.length < LIMITS.minEditLength || COMMON_WORDS.has(label)) return null;
  let best: Brand | null = null;
  for (const key of [label, ...deletes(label)]) {
    for (const brand of index.deletions.get(key) ?? []) {
      if (brand.label === label || !isOneEdit(label, brand.label) || likelyFalsePositive(label, brand.label)) continue;
      if (!best || brand.rank < best.rank) best = brand;
    }
  }
  return best;
}

/** A word that is (or looks exactly like) a top-10k brand name long enough to mean it */
function brandWord(word: string, index: BrandIndex): Brand | null {
  if (word.length < LIMITS.minBrandLength || CREDENTIAL_WORDS.has(word)) return null;
  const brand = index.byLabelSkeleton.get(skeleton(word));
  return brand && brand.label.length >= LIMITS.minBrandLength && isProtected(brand) ? brand : null;
}

/** brandWord, or failing that a one-letter typo of a top-1k brand ("login-mircosoft") */
function brandOrTypo(word: string, index: BrandIndex, allowTypo: boolean): { brand: Brand; typo: boolean } | null {
  const brand = brandWord(word, index);
  if (brand) return { brand, typo: false };
  const typo = allowTypo && !CREDENTIAL_WORDS.has(word) ? editDistanceMatch(word, index) : null;
  return typo ? { brand: typo, typo: true } : null;
}

/**
 * The label itself carries the trick: a non-ASCII letter, a digit the brand
 * doesn't have, or "rn" standing in for "m". Without this, "info" would be
 * a fake of "inf0" and "tom" of "torn".
 */
function usesSubstitution(label: string, brandLabel: string): boolean {
  if (/[^\x00-\x7f]/.test(label)) return true;
  if (/[0-9]/.test(label) && !/[0-9]/.test(brandLabel)) return true;
  return label.includes('rn') && !brandLabel.includes('rn');
}

/** "paypallogin", "secureapple": a credential word glued to a brand */
function gluedCredential(word: string, index: BrandIndex): { brand: Brand; keyword: string } | null {
  for (const keyword of CONCAT_WORDS) {
    if (word.length <= keyword.length) continue;
    const rest = word.startsWith(keyword) ? word.slice(keyword.length) : word.endsWith(keyword) ? word.slice(0, -keyword.length) : null;
    const brand = rest ? brandWord(rest, index) : null;
    // "cloudlogin", "mediasupport": run-together common words need a very top brand
    if (brand && (!brand.common || brand.rank <= LIMITS.commonWordTop)) return { brand, keyword };
  }
  return null;
}

const quote = (s: string) => `"${s}"`;

export function detectLookalike(host: string, index: BrandIndex): LookalikeReport {
  const clean = host.trim().toLowerCase().replace(/\.$/, '');
  const ascii = domainToASCII(clean) || clean;
  const unicode = domainToUnicode(ascii) || ascii;
  const report: LookalikeReport = {
    ascii, unicode, registrable: null, label: null, platform: null, rank: null, matches: [], mixedScript: [], scriptExempt: null,
  };

  const icann = parse(ascii);
  if (icann.isIp || !icann.domain || !icann.domainWithoutSuffix || !icann.publicSuffix) return report;
  // A tenant of a hosting platform is its own site: "trust-wallet-login" on vercel.app
  const tenant = parse(ascii, { allowPrivateDomains: true });
  const onPlatform = !!tenant.domain && !!tenant.domainWithoutSuffix && tenant.domain !== icann.domain;
  const parsed = onPlatform ? tenant : icann;
  if (!parsed.domain || !parsed.domainWithoutSuffix || !parsed.publicSuffix) return report;
  report.registrable = parsed.domain;
  report.platform = onPlatform ? icann.domain : null;

  // 1. The genuine article
  const rank = index.rankOf.get(parsed.domain);
  if (rank !== undefined) {
    report.rank = rank;
    return report;
  }

  const label = domainToUnicode(parsed.domainWithoutSuffix) || parsed.domainWithoutSuffix;
  report.label = label;
  const suffix = domainToUnicode(parsed.publicSuffix) || parsed.publicSuffix;
  const subLabels = parsed.subdomain ? parsed.subdomain.split('.').map((l) => domainToUnicode(l) || l) : [];
  const add = (kind: LookalikeKind, brand: Brand, why: string, countryCode?: boolean) => {
    if (!report.matches.some((m) => m.kind === kind && m.target === brand.display)) {
      report.matches.push({ kind, target: brand.display, targetRank: brand.rank, why, ...(countryCode !== undefined ? { countryCode } : {}) });
    }
  };

  for (const l of [...subLabels, label]) {
    const info = scriptInfo(l);
    if (info.mixed) report.mixedScript.push({ label: l, info });
  }

  // 2. Embedding: a popular domain spelled out in front of the real one. Hyphens split
  // words too ("paypal.com-login.info"), but a match must cross a dot and end before the
  // public suffix: "treasury.gov" in hm-treasury.gov.uk and "alice-it" are not embedding.
  const labels = unicode.split('.');
  const suffixStart = labels.length - suffix.split('.').length;
  const tokens = labels.flatMap((l, at) => l.split('-').filter(Boolean).map((text) => ({ text, at })));
  const ownSkeleton = skeleton(label);
  for (let i = 0; i < tokens.length; i++) {
    for (let n = 2; n <= 4 && i + n <= tokens.length; n++) {
      const span = tokens.slice(i, i + n);
      if (span[n - 1].at >= suffixStart || span[0].at === span[n - 1].at) continue;
      const text = span.map((t) => t.text).join('.');
      const brand = index.byDomainSkeleton.get(skeleton(text));
      if (!brand || brand.domain === parsed.domain || brand.label.length < LIMITS.minBrandLength || !isProtected(brand)) continue;
      // google.com inside google.com.au is the same brand on its own ccTLD
      if (skeleton(brand.label) === ownSkeleton) continue;
      add('embedding', brand, `has ${quote(text)} in front of its real domain, ${parsed.domain}`);
    }
  }

  // 3. Confusable skeleton of the registrable label
  const brand = index.byLabelSkeleton.get(ownSkeleton);
  if (brand && brand.label !== label && isProtected(brand) && usesSubstitution(label, brand.label)) {
    const info = scriptInfo(label);
    const tld = suffix.split('.').pop() ?? suffix;
    const ownScriptTld = info.wholeScript && (SCRIPT_TLDS[info.wholeScript]?.includes(tld) || scriptInfo(tld).wholeScript === info.wholeScript);
    if (ownScriptTld) report.scriptExempt = `${label} is written entirely in ${info.wholeScript} under .${tld}, a ${info.wholeScript} TLD`;
    else add('confusable', brand, `${quote(label)} renders like ${quote(brand.label)}`);
  }

  // 4 and 7. Brand words combined with other words, label by label
  for (const l of [...subLabels, label]) {
    const words = l.split('-').filter(Boolean);
    const credential = words.find((w) => CREDENTIAL_WORDS.has(w));
    const isWholeRegistrable = l === label && words.length === 1;
    for (const w of words) {
      const glued = gluedCredential(w, index);
      if (glued) add('credential-combo', glued.brand, `${quote(l)} joins the brand ${quote(glued.brand.label)} with ${quote(glued.keyword)}`);
    }
    if (isWholeRegistrable) continue;
    // A typo'd brand only counts next to a credential word ("login-mircosoft")
    const brands = words.map((w) => brandOrTypo(w, index, !!credential));
    const found = brands.find((b) => b !== null);
    if (!found) continue;
    const name = found.typo ? `${quote(words[brands.indexOf(found)])} (one letter off ${quote(found.brand.label)})` : quote(found.brand.label);
    if (credential) add('credential-combo', found.brand, `${quote(l)} pairs the brand ${name} with ${quote(credential)}`);
    // "office-japan": a common word with another word is usually just a name
    else if (words.length > 1 && (!found.brand.common || found.brand.rank <= LIMITS.commonWordTop) && brands.some((b) => b === null)) add('brand-word', found.brand, `${quote(l)} adds other words to the brand ${name}`);
  }

  // 5. One typo away from a top-1k brand
  const typo = editDistanceMatch(label, index);
  if (typo && !report.matches.some((m) => m.target === typo.display)) {
    add('edit-distance', typo, `${quote(label)} is one letter off ${quote(typo.label)}`);
  }

  // 6. A brand's exact name on a suffix it isn't ranked under
  const sameName = index.byLabel.get(label);
  if (sameName && label.length >= LIMITS.minBrandLength && (!sameName.common || sameName.rank <= LIMITS.commonWordTop) && sameName.domain !== parsed.domain) {
    const tld = parsed.publicSuffix.split('.').pop() ?? '';
    const where = onPlatform ? suffix : `.${suffix}`;
    add('tld-swap', sameName, `same name as ${sameName.display} on ${where}`, !onPlatform && (/^[a-z]{2}$/.test(tld) || tld.startsWith('xn--')));
  }

  report.matches.sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.targetRank - b.targetRank);
  return report;
}
