// IP2Proxy LITE local database (optional). Download a free LITE BIN file
// (e.g. IP2PROXY-LITE-PX2.BIN) from https://lite.ip2location.com and either
// put it in ./data/ or point IP2PROXY_DB_PATH at it. Without it, this source
// is silently left out.
import fs from 'fs';
import path from 'path';
import { IP2Proxy } from 'ip2proxy-nodejs';

export interface Ip2ProxyResult {
  isProxy: boolean;
  /** VPN, TOR, DCH (hosting), PUB, WEB, SES, RES, CPN, EPN */
  proxyType: string | null;
  countryCode: string | null;
  isp: string | null;
  usageType: string | null;
  threat: string | null;
  database: string;
}

const UNAVAILABLE = /NOT SUPPORTED|INVALID|MISSING|unavailable|IPV6 ADDRESS MISSING/i;

function clean(value: string | undefined): string | null {
  if (!value || value === '-' || UNAVAILABLE.test(value)) return null;
  return value;
}

function findDatabase(): string | null {
  const configured = process.env.IP2PROXY_DB_PATH?.trim();
  if (configured) return fs.existsSync(configured) ? configured : null;
  const dataDir = path.join(process.cwd(), 'data');
  try {
    const match = fs
      .readdirSync(dataDir)
      .filter((f) => /^IP2PROXY.*\.BIN$/i.test(f))
      .sort()
      .pop();
    return match ? path.join(dataDir, match) : null;
  } catch {
    return null;
  }
}

const globalForIp2p = globalThis as unknown as {
  __ip2proxy?: { file: string; mtimeMs: number; reader: IP2Proxy } | null;
};

async function getReader(): Promise<{ reader: IP2Proxy; file: string } | null> {
  const file = findDatabase();
  if (!file) return null;
  const mtimeMs = fs.statSync(file).mtimeMs;
  const cached = globalForIp2p.__ip2proxy;
  if (cached && cached.file === file && cached.mtimeMs === mtimeMs) return cached;

  cached?.reader.close();
  const reader = new IP2Proxy();
  if ((await reader.openAsync(file)) !== 0) {
    console.error('Could not open IP2Proxy database:', file);
    globalForIp2p.__ip2proxy = null;
    return null;
  }
  globalForIp2p.__ip2proxy = { file, mtimeMs, reader };
  return { reader, file };
}

export function isIp2ProxyAvailable(): boolean {
  return findDatabase() !== null;
}

export async function checkIp2Proxy(ip: string): Promise<Ip2ProxyResult | null> {
  try {
    const db = await getReader();
    if (!db) return null;
    const data = await db.reader.getAllAsync(ip);
    if (data.isProxy < 0) return null;
    return {
      isProxy: data.isProxy > 0,
      proxyType: data.isProxy > 0 ? clean(data.proxyType) : null,
      countryCode: clean(data.countryShort),
      isp: clean(data.isp),
      usageType: clean(data.usageType),
      threat: clean(data.threat),
      database: path.basename(db.file),
    };
  } catch (error) {
    console.error('IP2Proxy lookup error:', error);
    return null;
  }
}
