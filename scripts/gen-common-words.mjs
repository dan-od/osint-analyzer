// Regenerates src/lib/lookalike/common-words.json from Chromium's list of the
// 10,000 most common English words, which Chrome's look-alike checks use to
// avoid false positives ("simple", "cloud" and "media" are words, not brands).
// Pinned to one Chromium commit. Chromium is BSD-3-Clause licensed.
// Usage: node scripts/gen-common-words.mjs
import fs from 'fs';
import path from 'path';

const COMMIT = 'fc28c87236198c79c6ca07fa2f6bc6ca35324e53';
const URL = `https://raw.githubusercontent.com/chromium/chromium/${COMMIT}/components/url_formatter/spoof_checks/common_words/data/common_words.gperf`;
const OUT = path.join(process.cwd(), 'src', 'lib', 'lookalike', 'common-words.json');

const response = await fetch(URL);
if (!response.ok) throw new Error(`${URL}: HTTP ${response.status}`);
const words = [];
for (const line of (await response.text()).split('\n')) {
  const m = /^([a-z0-9-]+), \d+$/.exec(line.trim());
  if (m) words.push(m[1]);
}
if (words.length < 9000) throw new Error(`Only ${words.length} words parsed; the file format may have changed`);

fs.writeFileSync(OUT, JSON.stringify({ source: URL, words }) + '\n');
console.log(`Wrote ${words.length} words (Chromium ${COMMIT.slice(0, 10)}) to ${path.relative(process.cwd(), OUT)}`);
