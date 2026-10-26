// Unicode confusable skeletons (UTS #39 section 4) and script mixing (section 5).
// Two strings that render alike share a skeleton: "g00gle", "paypa1",
// "rnicrosoft" and Cyrillic "аpple" all collapse onto the brand they copy.
import confusables from './confusables.json';

const MAP: Record<string, string> = (confusables as { map: Record<string, string> }).map;
export const CONFUSABLES_VERSION: string = (confusables as { version: string }).version;

/** Digit swaps UTS #39 doesn't fold (it already maps 0 to O and 1 to l) */
const LEET: Record<string, string> = { '3': 'e', '5': 's' };

// RegExp constructors: the tsconfig target rejects the u flag on literals
const MARKS = new RegExp('\\p{Mn}', 'gu');

/**
 * skeleton(s) = NFD(map(NFD(s))), lower-cased, with combining marks dropped
 * so "googlé" matches "google" too (Chrome strips diacritics the same way).
 */
export function skeleton(input: string): string {
  let out = '';
  for (const ch of input.toLowerCase().normalize('NFD')) out += LEET[ch] ?? MAP[ch] ?? ch;
  return out.normalize('NFD').toLowerCase().replace(MARKS, '');
}

// Scripts a domain label can plausibly use. Anything else counts as "Other".
const SCRIPTS = [
  'Latin', 'Cyrillic', 'Greek', 'Armenian', 'Georgian', 'Hebrew', 'Arabic', 'Syriac', 'Thaana',
  'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya', 'Tamil', 'Telugu', 'Kannada', 'Malayalam',
  'Sinhala', 'Thai', 'Lao', 'Tibetan', 'Myanmar', 'Khmer', 'Ethiopic', 'Cherokee', 'Mongolian',
  'Han', 'Hiragana', 'Katakana', 'Hangul', 'Bopomofo',
] as const;
const SCRIPT_TESTS = SCRIPTS.map((name) => ({ name, re: new RegExp(`^\\p{Script=${name}}$`, 'u') }));
const NEUTRAL = new RegExp('^[\\p{Script=Common}\\p{Script=Inherited}]$', 'u');

export function scriptOf(ch: string): string | null {
  if (NEUTRAL.test(ch)) return null;
  return SCRIPT_TESTS.find((s) => s.re.test(ch))?.name ?? 'Other';
}

/** UTS #39 "highly restrictive": one script, or Latin with the CJK sets */
const ALLOWED_MIXES = [
  ['Latin', 'Han', 'Hiragana', 'Katakana'],
  ['Latin', 'Han', 'Bopomofo'],
  ['Latin', 'Han', 'Hangul'],
];

export interface ScriptInfo {
  /** Distinct scripts in the label, Common/Inherited (digits, hyphen, marks) ignored */
  scripts: string[];
  /** More than one script, outside the CJK combinations UTS #39 allows */
  mixed: boolean;
  /** Every character is in a single script other than Latin */
  wholeScript: string | null;
  /** The characters outside the label's main script, for the finding text */
  odd: { char: string; codePoint: string; script: string }[];
}

export function scriptInfo(label: string): ScriptInfo {
  const counts = new Map<string, number>();
  const chars: { char: string; script: string }[] = [];
  for (const ch of Array.from(label)) {
    const script = scriptOf(ch);
    if (!script) continue;
    chars.push({ char: ch, script });
    counts.set(script, (counts.get(script) ?? 0) + 1);
  }
  const scripts = Array.from(counts.keys());
  const mixed = scripts.length > 1 && !ALLOWED_MIXES.some((set) => scripts.every((s) => set.includes(s)));
  // The main script is Latin when present (the brand being copied is usually Latin), else the commonest
  const main = counts.has('Latin') ? 'Latin' : scripts.slice().sort((a, b) => (counts.get(b) ?? 0) - (counts.get(a) ?? 0))[0];
  const odd = mixed
    ? chars
        .filter((c) => c.script !== main)
        .map((c) => ({ char: c.char, codePoint: `U+${c.char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`, script: c.script }))
    : [];
  // Main script first: "mixes Latin and Cyrillic"
  const ordered = main ? [main, ...scripts.filter((s) => s !== main)] : scripts;
  return { scripts: ordered, mixed, wholeScript: scripts.length === 1 && scripts[0] !== 'Latin' ? scripts[0] : null, odd };
}
