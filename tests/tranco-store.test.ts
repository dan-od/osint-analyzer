import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTrancoStore } from '../src/lib/server/lookalike';
import { BUNDLED_TRANCO_LIST_ID, configurationProblem, listAgeDays, trancoConfiguration } from '../src/lib/lookalike/tranco-list';

const RANKING = fs.readFileSync(new URL('./fixtures/tranco/ranking.csv', import.meta.url), 'utf8');
const NOW = Date.parse('2026-10-23T12:00:00Z');
const DAY = 86_400_000;
const PROVIDERS = ['crux', 'farsight', 'majestic', 'umbrella'];

const dirs: string[] = [];
function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tranco-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** A bundled snapshot whose data ends on `endDate` */
function bundle(endDate: string, extra: Record<string, unknown> = {}): string {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, 'BUNDLE1.csv.gz'), zlib.gzipSync(RANKING));
  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify({ listId: 'BUNDLE1', startDate: '2026-09-01', endDate, providers: PROVIDERS, rows: 28, createdOn: null, file: 'BUNDLE1.csv.gz', ...extra })
  );
  return dir;
}

type Route = { status: number; body: unknown } | ((init?: RequestInit) => { status: number; body: unknown });

function fakeFetch(routes: Record<string, Route>) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const route = routes[url];
    if (!route) throw new TypeError(`fetch failed: ${url}`);
    const { status, body } = typeof route === 'function' ? route(init) : route;
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
  });
}

const quiet = () => undefined;

function store(options: { bundleDir?: string; fetch?: ReturnType<typeof fakeFetch>; credentials?: { email: string; key: string } | null; now?: number } = {}) {
  return createTrancoStore({
    bundleDir: options.bundleDir ?? tempDir(),
    cacheDir: tempDir(),
    fetch: (options.fetch ?? fakeFetch({})) as unknown as typeof fetch,
    credentials: options.credentials ?? null,
    now: () => options.now ?? NOW,
    pollMs: 1,
    minRows: 10,
    log: quiet,
  });
}

describe('list configuration', () => {
  it('asks Tranco for the default sources without Cloudflare Radar, 30 days to yesterday', () => {
    expect(trancoConfiguration('2026-10-22')).toEqual({
      providers: PROVIDERS,
      startDate: '2026-09-23',
      endDate: '2026-10-22',
      combinationMethod: 'dowdall',
      listPrefix: 'full',
      filterPLD: 'on',
    });
  });

  it('rejects lists with Radar data or subdomains', () => {
    expect(configurationProblem({ providers: ['crux', 'radar'], filterPLD: 'on' })).toMatch(/Radar/);
    expect(configurationProblem({ providers: PROVIDERS, filterPLD: 'off' })).toMatch(/subdomains/);
    expect(configurationProblem({ providers: PROVIDERS, filterPLD: 'on' })).toBeNull();
  });

  it('counts age from the last day of data', () => {
    expect(listAgeDays({ endDate: '2026-10-22' }, NOW)).toBe(1);
    expect(listAgeDays({ endDate: '2026-10-15' }, NOW)).toBe(8);
  });

  it('records the bundled list ID in the code, matching the bundled manifest', () => {
    const manifest = path.join(process.cwd(), 'assets', 'tranco', 'manifest.json');
    if (BUNDLED_TRANCO_LIST_ID === null) {
      expect(fs.existsSync(manifest)).toBe(false);
    } else {
      const meta = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      expect(meta.listId).toBe(BUNDLED_TRANCO_LIST_ID);
      expect(configurationProblem({ providers: meta.providers, filterPLD: 'on' })).toBeNull();
      expect(fs.existsSync(path.join(process.cwd(), 'assets', 'tranco', meta.file))).toBe(true);
    }
  });
});

describe('fail safe', () => {
  it('skips with a reason when there is no list at all', () => {
    const state = store().get();
    expect(state).toEqual({ ok: false, reason: expect.stringMatching(/No popularity list available\. This server has no Tranco API key/) });
  });

  it('uses a bundled list while its data is at most 7 days old', () => {
    const state = store({ bundleDir: bundle('2026-10-16') }).get();
    expect(state.ok && state.list.listId).toBe('BUNDLE1');
    expect(state.ok && state.ageDays).toBe(7);
    expect(state.ok && state.index.rankOf.get('google.com')).toBe(1);
  });

  it('skips once the list is more than 7 days old, naming the list', () => {
    const state = store({ bundleDir: bundle('2026-10-15') }).get();
    expect(state.ok).toBe(false);
    expect(!state.ok && state.reason).toMatch(/Tranco BUNDLE1, data to 2026-10-15\) is 8 days old; look-alike checks need one under 7 days/);
  });

  it('refuses a bundled list that includes Radar data', () => {
    const state = store({ bundleDir: bundle('2026-10-20', { providers: ['crux', 'radar'] }) }).get();
    expect(state.ok).toBe(false);
  });

  it('skips with the error when the download fails and the list is stale', async () => {
    const fetch = fakeFetch({ 'https://tranco-list.eu/api/lists/create': { status: 503, body: 'down' } });
    const s = store({ bundleDir: bundle('2026-10-10'), fetch, credentials: { email: 'a@example.com', key: 'k' } });
    s.get(); // starts the refresh in the background
    await s.refresh();
    const state = s.get();
    expect(!state.ok && state.reason).toMatch(/13 days old.*Last refresh failed: PUT \/lists\/create: HTTP 503/);
  });

  it('keeps a list that is still fresh when a refresh fails', async () => {
    const fetch = fakeFetch({ 'https://tranco-list.eu/api/lists/create': { status: 503, body: 'down' } });
    const s = store({ bundleDir: bundle('2026-10-18'), fetch, credentials: { email: 'a@example.com', key: 'k' } });
    s.get();
    await s.refresh();
    expect(s.get().ok).toBe(true);
    expect(s.status().lastError).toMatch(/HTTP 503/);
  });
});

describe('refresh through the Tranco API', () => {
  const config = { ...trancoConfiguration('2026-10-22') };

  it('generates a list, waits for it, downloads the top 100k and switches to it', async () => {
    let polls = 0;
    const fetch = fakeFetch({
      'https://tranco-list.eu/api/lists/create': (init) => {
        expect(init?.method).toBe('PUT');
        expect(JSON.parse(String(init?.body))).toEqual(config);
        expect((init?.headers as Record<string, string>).Authorization).toBe(`Basic ${Buffer.from('a@example.com:k').toString('base64')}`);
        return { status: 200, body: { list_id: 'NEW42', available: false } };
      },
      'https://tranco-list.eu/api/lists/id/NEW42': () => ({
        status: 200,
        body: { list_id: 'NEW42', available: ++polls > 1, failed: false, created_on: '2026-10-23T08:00:00', configuration: config },
      }),
      'https://tranco-list.eu/download/NEW42/100000': { status: 200, body: RANKING },
    });
    const s = store({ bundleDir: bundle('2026-10-10'), fetch, credentials: { email: 'a@example.com', key: 'k' } });
    expect(s.get().ok).toBe(false); // stale bundle; the refresh starts now
    await s.refresh();
    const state = s.get();
    expect(state.ok && state.list).toMatchObject({ listId: 'NEW42', startDate: '2026-09-23', endDate: '2026-10-22', providers: PROVIDERS });
    expect(polls).toBe(2);
  });

  it('rejects a generated list whose configuration includes Radar', async () => {
    const fetch = fakeFetch({
      'https://tranco-list.eu/api/lists/create': { status: 200, body: { list_id: 'BAD1', available: true } },
      'https://tranco-list.eu/api/lists/id/BAD1': { status: 200, body: { available: true, configuration: { ...config, providers: [...PROVIDERS, 'radar'] } } },
    });
    const s = store({ fetch, credentials: { email: 'a@example.com', key: 'k' } });
    await s.refresh();
    expect(s.status().lastError).toMatch(/Radar/);
    expect(s.get().ok).toBe(false);
  });

  it('never calls the API without credentials', () => {
    const fetch = fakeFetch({});
    store({ bundleDir: bundle('2026-10-01'), fetch }).get();
    expect(fetch).not.toHaveBeenCalled();
  });
});
