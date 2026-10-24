// Domain registration data over RDAP (RFC 9082/9083): free, no API key.
//
// 1. IANA's bootstrap file (data.iana.org/rdap/dns.json, cached 24 h) maps
//    each TLD to its registry's RDAP server.
// 2. GET <server>/domain/<name> (Accept: application/rdap+json, 5 s timeout).
//    A 404 from the registry's own server means "not registered".
// 3. No server for the TLD, or it failed: https://rdap.org/domain/<name>.
// 4. Still nothing: port-43 WHOIS (whoiser), parsing the dates out.
// Every lookup failing returns null; the caller then skips the domain-age
// finding instead of counting it as risky. Results are cached per domain.
//
// No "@/..." imports, so the tests can load this file directly.

export interface DomainRegistration {
  createdAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  /** Whole days since createdAt; null when the registration date isn't published */
  ageDays: number | null;
  /** The entity with role "registrar" (its vCard "fn"), or WHOIS "Registrar" */
  registrar: string | null;
  /** RDAP statuses ("client hold", "server transfer prohibited", ...); WHOIS ones are normalised to match */
  status: string[];
  nameservers: string[];
  source: 'rdap' | 'whois';
}

export type WhoisRecord = Record<string, unknown>;

export interface RdapDeps {
  fetch?: typeof fetch;
  /** Port-43 lookup; returns whoiser's parsed result (one object per WHOIS server) */
  whois?: (domain: string) => Promise<WhoisRecord>;
  now?: () => number;
}

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const RDAP_ORG = 'https://rdap.org/domain/';
const TIMEOUT_MS = 5000;
const DAY_MS = 24 * 60 * 60 * 1000;
const BOOTSTRAP_TTL_MS = DAY_MS;
const RESULT_TTL_MS = DAY_MS;
/** Misses are retried sooner: a network blip shouldn't hide a domain for a day */
const MISS_TTL_MS = 60 * 60 * 1000;

type Fetched = { kind: 'found'; json: Record<string, unknown> } | { kind: 'not-found' } | { kind: 'error' };

async function defaultWhois(domain: string): Promise<WhoisRecord> {
  const whoiser = await import('whoiser');
  return (await whoiser.domain(domain, { timeout: TIMEOUT_MS, follow: 1 })) as WhoisRecord;
}

export function createRdapClient(deps: RdapDeps = {}) {
  const fetchFn = deps.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const whois = deps.whois ?? defaultWhois;
  const now = deps.now ?? Date.now;

  let bootstrap: { servers: Map<string, string>; loadedAt: number } | null = null;
  let bootstrapLoading: Promise<void> | null = null;
  const cache = new Map<string, { value: DomainRegistration | null; expires: number }>();

  async function loadBootstrap(): Promise<void> {
    try {
      const response = await fetchFn(BOOTSTRAP_URL, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bootstrap = { servers: parseBootstrap(await response.json()), loadedAt: now() };
    } catch (error) {
      // Keep the previous map if there is one; without it every TLD goes to rdap.org
      console.warn('[rdap] could not load the IANA bootstrap file:', (error as Error).message);
      if (bootstrap) bootstrap.loadedAt = now() - BOOTSTRAP_TTL_MS + 10 * 60 * 1000; // retry in 10 min
    }
  }

  async function serverFor(tld: string): Promise<string | null> {
    if (!bootstrap || now() - bootstrap.loadedAt > BOOTSTRAP_TTL_MS) {
      bootstrapLoading ??= loadBootstrap().finally(() => (bootstrapLoading = null));
      await bootstrapLoading;
    }
    return bootstrap?.servers.get(tld) ?? null;
  }

  async function get(url: string): Promise<Fetched> {
    try {
      const response = await fetchFn(url, {
        headers: { Accept: 'application/rdap+json' },
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (response.status === 404) return { kind: 'not-found' };
      if (!response.ok) return { kind: 'error' };
      const json = (await response.json()) as Record<string, unknown>;
      return json && typeof json === 'object' && !('errorCode' in json) ? { kind: 'found', json } : { kind: 'error' };
    } catch {
      return { kind: 'error' };
    }
  }

  async function resolve(domain: string): Promise<DomainRegistration | null> {
    const tld = domain.slice(domain.lastIndexOf('.') + 1);
    const server = await serverFor(tld);
    if (server) {
      const answer = await get(`${server}domain/${encodeURIComponent(domain)}`);
      if (answer.kind === 'found') return parseRdap(answer.json, now());
      // The registry itself says the domain doesn't exist
      if (answer.kind === 'not-found') return null;
    }
    const viaRdapOrg = await get(`${RDAP_ORG}${encodeURIComponent(domain)}`);
    if (viaRdapOrg.kind === 'found') return parseRdap(viaRdapOrg.json, now());
    try {
      return parseWhois(await whois(domain), now());
    } catch {
      return null;
    }
  }

  /** Registration data for a domain, or null when no source has any */
  async function lookupDomain(domain: string): Promise<DomainRegistration | null> {
    const name = domain.trim().toLowerCase().replace(/\.$/, '');
    const hit = cache.get(name);
    if (hit && hit.expires > now()) return hit.value;
    const value = await resolve(name);
    cache.set(name, { value, expires: now() + (value ? RESULT_TTL_MS : MISS_TTL_MS) });
    if (cache.size > 5000) {
      Array.from(cache.entries()).forEach(([key, entry]) => entry.expires <= now() && cache.delete(key));
    }
    return value;
  }

  return { lookupDomain };
}

/** TLD -> RDAP base URL (with a trailing slash), from IANA's dns.json */
export function parseBootstrap(json: unknown): Map<string, string> {
  const servers = new Map<string, string>();
  const services = (json as { services?: [string[], string[]][] })?.services ?? [];
  for (const [tlds, urls] of services) {
    const url = urls.find((u) => u.startsWith('https://')) ?? urls[0];
    if (!url) continue;
    for (const tld of tlds) servers.set(tld.toLowerCase(), url.endsWith('/') ? url : `${url}/`);
  }
  return servers;
}

function ageInDays(createdAt: string | null, nowMs: number): number | null {
  if (!createdAt) return null;
  const created = Date.parse(createdAt);
  return Number.isNaN(created) ? null : Math.max(0, Math.floor((nowMs - created) / DAY_MS));
}

function isoOrNull(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  const time = Date.parse(value.trim());
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

type RdapEntity = { roles?: string[]; vcardArray?: [string, [string, unknown, string, unknown][]]; entities?: RdapEntity[] };

function registrarName(entities: RdapEntity[] | undefined): string | null {
  for (const entity of entities ?? []) {
    if (entity.roles?.includes('registrar')) {
      const fn = entity.vcardArray?.[1]?.find((field) => field[0] === 'fn')?.[3];
      if (typeof fn === 'string' && fn.trim()) return fn.trim();
    }
    const nested = registrarName(entity.entities);
    if (nested) return nested;
  }
  return null;
}

/** An RDAP domain object (RFC 9083) in our shape */
export function parseRdap(json: Record<string, unknown>, nowMs: number): DomainRegistration {
  const events = (json.events as { eventAction?: string; eventDate?: string }[] | undefined) ?? [];
  const event = (action: string) => isoOrNull(events.find((e) => e.eventAction === action)?.eventDate);
  const createdAt = event('registration');
  return {
    createdAt,
    updatedAt: event('last changed'),
    expiresAt: event('expiration'),
    ageDays: ageInDays(createdAt, nowMs),
    registrar: registrarName(json.entities as RdapEntity[] | undefined),
    status: ((json.status as string[] | undefined) ?? []).map((s) => s.toLowerCase()),
    nameservers: ((json.nameservers as { ldhName?: string }[] | undefined) ?? [])
      .map((n) => n.ldhName?.toLowerCase())
      .filter((n): n is string => !!n),
    source: 'rdap',
  };
}

/** "clientHold https://icann.org/epp#clientHold" -> "client hold" (the RDAP spelling) */
function normaliseWhoisStatus(status: string): string {
  return status
    .split(/\s+/)[0]
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase();
}

function asList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && !!v.trim());
  return typeof value === 'string' && value.trim() ? [value] : [];
}

/** whoiser's result (one object per WHOIS server queried) in our shape; null if it has no dates or registrar */
export function parseWhois(record: WhoisRecord, nowMs: number): DomainRegistration | null {
  const servers = Object.values(record).filter((v): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v));
  const pick = (...keys: string[]) => {
    for (const server of servers) for (const key of keys) if (server[key]) return server[key];
    return undefined;
  };
  const createdAt = isoOrNull(pick('Created Date', 'Creation Date', 'Registration Time', 'created'));
  const expiresAt = isoOrNull(pick('Expiry Date', 'Registry Expiry Date', 'Expiration Date', 'paid-till'));
  const updatedAt = isoOrNull(pick('Updated Date', 'Last Modified', 'last-modified'));
  const registrarValue = pick('Registrar', 'registrar');
  const registrar = typeof registrarValue === 'string' && registrarValue.trim() ? registrarValue.trim() : null;
  if (!createdAt && !expiresAt && !registrar) return null;
  return {
    createdAt,
    updatedAt,
    expiresAt,
    ageDays: ageInDays(createdAt, nowMs),
    registrar,
    status: Array.from(new Set(asList(pick('Domain Status', 'status')).map(normaliseWhoisStatus))),
    nameservers: Array.from(new Set(asList(pick('Name Server', 'nserver')).map((n) => n.toLowerCase()))),
    source: 'whois',
  };
}

const defaultClient = createRdapClient();

/** Registration data for a domain (RDAP, then rdap.org, then WHOIS); null when nothing answers */
export const lookupDomain = defaultClient.lookupDomain;
