// Regenerates src/lib/lookalike/confusables.json from Unicode's UTS #39
// confusables.txt (source code point -> prototype string). Pinned to one
// Unicode version so the skeletons, and so the findings, are reproducible.
// Usage: node scripts/gen-confusables.mjs
import fs from 'fs';
import path from 'path';

const VERSION = '18.0.0';
const URL = `https://www.unicode.org/Public/${VERSION}/security/confusables.txt`;
const OUT = path.join(process.cwd(), 'src', 'lib', 'lookalike', 'confusables.json');

const response = await fetch(URL);
if (!response.ok) throw new Error(`${URL}: HTTP ${response.status}`);
const text = await response.text();

const map = {};
for (const line of text.split('\n')) {
  const m = /^([0-9A-F]+)\s*;\s*([0-9A-F ]+?)\s*;\s*MA/.exec(line);
  if (!m) continue;
  const from = String.fromCodePoint(parseInt(m[1], 16));
  map[from] = m[2].split(' ').map((h) => String.fromCodePoint(parseInt(h, 16))).join('');
}
const count = Object.keys(map).length;
if (count < 6000) throw new Error(`Only ${count} mappings parsed; the file format may have changed`);

fs.writeFileSync(OUT, JSON.stringify({ version: VERSION, source: URL, map }) + '\n');
console.log(`Wrote ${count} mappings (Unicode ${VERSION}) to ${path.relative(process.cwd(), OUT)}`);
