// Bundles a Tranco list in assets/tranco/ (top 100k, gzipped) and records its
// permanent ID in src/lib/lookalike/tranco-list.ts, so a new container can run
// look-alike checks before its first download, and results can be reproduced.
//
//   npm run tranco:snapshot            generate a new list (needs TRANCO_API_EMAIL
//                                      and TRANCO_API_KEY, e.g. in .env.local)
//   npm run tranco:snapshot -- <ID>    bundle a list you created on tranco-list.eu
//
// Either way the list must not include Cloudflare Radar (CC BY-NC) and must
// rank registrable domains. Same rules as src/lib/lookalike/tranco-list.ts.
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

const API = 'https://tranco-list.eu/api';
const PROVIDERS = ['crux', 'farsight', 'majestic', 'umbrella'];
const WINDOW_DAYS = 30;
const ROWS = 100_000;
const OUT_DIR = path.join(process.cwd(), 'assets', 'tranco');
const CODE = path.join(process.cwd(), 'src', 'lib', 'lookalike', 'tranco-list.ts');

const email = process.env.TRANCO_API_EMAIL?.trim();
const key = process.env.TRANCO_API_KEY?.trim();
const auth = email && key ? { Authorization: `Basic ${Buffer.from(`${email}:${key}`).toString('base64')}` } : {};

async function call(url, init = {}) {
  const response = await fetch(url, { ...init, headers: { ...auth, ...(init.headers ?? {}) } });
  if (!response.ok) throw new Error(`${init.method ?? 'GET'} ${url}: HTTP ${response.status} ${(await response.text()).slice(0, 300)}`);
  return response;
}

let listId = process.argv[2]?.trim();
if (!listId) {
  if (!email || !key) throw new Error('Set TRANCO_API_EMAIL and TRANCO_API_KEY (tranco-list.eu account page), or pass a list ID');
  const end = new Date(Date.now() - 86_400_000);
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - (WINDOW_DAYS - 1));
  const config = {
    providers: PROVIDERS,
    startDate: start.toISOString().slice(0, 10),
    endDate: end.toISOString().slice(0, 10),
    combinationMethod: 'dowdall',
    listPrefix: 'full',
    filterPLD: 'on',
  };
  const created = await (await call(`${API}/lists/create`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) })).json();
  listId = created.list_id;
  console.log(`Requested list ${listId} (${config.startDate} to ${config.endDate}, ${PROVIDERS.join(', ')})`);
}

let info = await (await call(`${API}/lists/id/${listId}`)).json();
while (!info.available) {
  if (info.failed) throw new Error(`Tranco failed to generate list ${listId}`);
  console.log(`Waiting for list ${listId} (${info.jobs_ahead ?? '?'} jobs ahead)...`);
  await new Promise((r) => setTimeout(r, 15_000));
  info = await (await call(`${API}/lists/id/${listId}`)).json();
}
const config = info.configuration ?? {};
if (!Array.isArray(config.providers)) throw new Error(`List ${listId} has no configuration`);
if (config.providers.includes('radar')) throw new Error(`List ${listId} includes Cloudflare Radar data (CC BY-NC); create one without it`);
if (config.filterPLD !== 'on') throw new Error(`List ${listId} ranks subdomains; create one with "pay-level domains only"`);

const text = await (await call(`https://tranco-list.eu/download/${listId}/${ROWS}`)).text();
const rows = text.split('\n').filter((l) => /^\d+,/.test(l)).length;
if (rows < 50_000) throw new Error(`List ${listId} has only ${rows} rows`);

fs.mkdirSync(OUT_DIR, { recursive: true });
for (const old of fs.readdirSync(OUT_DIR)) if (old.endsWith('.csv.gz')) fs.rmSync(path.join(OUT_DIR, old));
const file = `${listId}.csv.gz`;
fs.writeFileSync(path.join(OUT_DIR, file), zlib.gzipSync(text, { level: 9 }));
const manifest = {
  listId,
  startDate: config.startDate,
  endDate: config.endDate,
  providers: config.providers,
  rows,
  createdOn: info.created_on ?? null,
  file,
  source: `https://tranco-list.eu/list/${listId}`,
};
fs.writeFileSync(path.join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

const code = fs.readFileSync(CODE, 'utf8');
const updated = code.replace(/export const BUNDLED_TRANCO_LIST_ID: string \| null = [^;]+;/, `export const BUNDLED_TRANCO_LIST_ID: string | null = '${listId}';`);
if (updated === code && !code.includes(`'${listId}'`)) throw new Error(`Could not record the list ID in ${CODE}`);
fs.writeFileSync(CODE, updated);

console.log(`Bundled Tranco list ${listId}: ${rows} rows, data ${config.startDate} to ${config.endDate}`);
console.log(`  ${path.relative(process.cwd(), path.join(OUT_DIR, file))} (${Math.round(fs.statSync(path.join(OUT_DIR, file)).size / 1024)} KB)`);
console.log(`  ID recorded in ${path.relative(process.cwd(), CODE)}; mention it in the commit message`);
