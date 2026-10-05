// Free IP blocklist feeds, cached on disk (data/feeds) and refreshed once a
// day. Entries can be single IPs or CIDR blocks; lookups binary-search merged
// ranges, so a /16 in FireHOL matches every address inside it.
import fs from 'fs';
import path from 'path';
import { parseCidr, type ParsedIp } from '@/lib/ip';
import type { BlocklistSourceResult } from '@/types';
import { FEED_META, type FeedMeta } from '@/lib/blocklist-meta';

const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const DOWNLOAD_TIMEOUT_MS = 20_000;

type FeedDef = FeedMeta;

export const FEEDS: FeedDef[] = FEED_META;

interface RangeSet {
  starts: bigint[];
  ends: bigint[];
}

interface FeedIndex {
  v4: RangeSet;
  v6: RangeSet;
  entries: number;
  fetchedAt: number;
}

const globalForFeeds = globalThis as unknown as {
  __osintFeeds?: Map<string, FeedIndex>;
  __osintFeedDownloads?: Map<string, Promise<void>>;
};
const indexes = (globalForFeeds.__osintFeeds ??= new Map());
const downloads = (globalForFeeds.__osintFeedDownloads ??= new Map());

function feedsDir(): string {
  const dir = process.env.FEEDS_DIR?.trim() || path.join(process.cwd(), 'data', 'feeds');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function buildRangeSet(ranges: { start: bigint; end: bigint }[]): RangeSet {
  ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const starts: bigint[] = [];
  const ends: bigint[] = [];
  for (const r of ranges) {
    const last = ends.length - 1;
    if (last >= 0 && r.start <= ends[last] + BigInt(1)) {
      if (r.end > ends[last]) ends[last] = r.end;
    } else {
      starts.push(r.start);
      ends.push(r.end);
    }
  }
  return { starts, ends };
}

export function parseFeed(text: string, fetchedAt: number): FeedIndex {
  const v4: { start: bigint; end: bigint }[] = [];
  const v6: { start: bigint; end: bigint }[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/[#;].*$/, '').trim();
    if (!line) continue;
    const token = line.split(/[\s,]+/)[0];
    const range = parseCidr(token);
    if (!range) continue;
    (range.version === 4 ? v4 : v6).push(range);
  }
  return { v4: buildRangeSet(v4), v6: buildRangeSet(v6), entries: v4.length + v6.length, fetchedAt };
}

function contains(set: RangeSet, value: bigint): boolean {
  let lo = 0;
  let hi = set.starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (set.starts[mid] <= value) {
      if (set.ends[mid] >= value) return true;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return false;
}

async function download(feed: FeedDef): Promise<void> {
  const response = await fetch(feed.url, {
    headers: { 'User-Agent': 'osint-analyzer/1.0 (+blocklist cache, daily)' },
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const text = await response.text();
  const now = Date.now();
  const index = parseFeed(text, now);
  const file = path.join(feedsDir(), `${feed.id}.txt`);
  fs.writeFileSync(`${file}.tmp`, text);
  fs.renameSync(`${file}.tmp`, file);
  indexes.set(feed.id, index);
}

function refresh(feed: FeedDef): Promise<void> {
  let pending = downloads.get(feed.id);
  if (!pending) {
    pending = download(feed)
      .catch((error) => console.error(`Blocklist feed ${feed.id} refresh failed:`, (error as Error).message))
      .finally(() => downloads.delete(feed.id));
    downloads.set(feed.id, pending);
  }
  return pending;
}

/** Returns the feed index, loading from disk or downloading as needed. */
async function getFeed(feed: FeedDef): Promise<FeedIndex | null> {
  let index = indexes.get(feed.id);
  if (!index) {
    const file = path.join(feedsDir(), `${feed.id}.txt`);
    if (fs.existsSync(file)) {
      index = parseFeed(fs.readFileSync(file, 'utf8'), fs.statSync(file).mtimeMs);
      indexes.set(feed.id, index);
    }
  }
  if (!index) {
    await refresh(feed);
    return indexes.get(feed.id) ?? null;
  }
  // Stale data is still used for this lookup while the refresh runs in the background
  if (Date.now() - index.fetchedAt > MAX_AGE_MS) void refresh(feed);
  return index;
}

export async function checkIpFeeds(
  ip: ParsedIp,
  onResult?: (result: BlocklistSourceResult) => void
): Promise<BlocklistSourceResult[]> {
  return Promise.all(
    FEEDS.map(async (feed): Promise<BlocklistSourceResult> => {
      const base = { id: feed.id, name: feed.name, kind: 'feed' as const, trust: feed.trust };
      const index = await getFeed(feed);
      if (!index) return { ...base, status: 'error', detail: 'feed could not be downloaded' };
      const listed = contains(ip.version === 4 ? index.v4 : index.v6, ip.value);
      const age = Math.round((Date.now() - index.fetchedAt) / 3_600_000);
      return { ...base, status: listed ? 'listed' : 'clean', detail: `${index.entries} entries, updated ${age}h ago` } as BlocklistSourceResult;
    }).map((p) => p.then((r) => {
      onResult?.(r);
      return r;
    }))
  );
}

/** Warm the cache (e.g. before a bulk job) without blocking on failures. */
export async function preloadFeeds(): Promise<void> {
  await Promise.all(FEEDS.map((feed) => getFeed(feed).catch(() => null)));
}

export interface FeedStatus {
  id: string;
  name: string;
  entries: number | null;
  updatedAt: string | null;
}

/** What's in the local feed cache, without downloading anything */
export function feedStatus(): FeedStatus[] {
  return FEEDS.map((feed) => {
    const index = indexes.get(feed.id);
    if (index) return { id: feed.id, name: feed.name, entries: index.entries, updatedAt: new Date(index.fetchedAt).toISOString() };
    const file = path.join(feedsDir(), `${feed.id}.txt`);
    if (!fs.existsSync(file)) return { id: feed.id, name: feed.name, entries: null, updatedAt: null };
    const parsed = parseFeed(fs.readFileSync(file, 'utf8'), fs.statSync(file).mtimeMs);
    indexes.set(feed.id, parsed);
    return { id: feed.id, name: feed.name, entries: parsed.entries, updatedAt: new Date(parsed.fetchedAt).toISOString() };
  });
}
