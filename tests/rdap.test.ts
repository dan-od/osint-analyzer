import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { createRdapClient, parseBootstrap, type WhoisRecord } from '../src/lib/rdap';

// Saved responses (fetched 2026-10-23): IANA bootstrap, Verisign RDAP for
// google.com, CIRA RDAP for cira.ca, and CIRA's 404 for an unregistered .ca
const fixture = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/rdap/${name}`, import.meta.url), 'utf8'));
const IANA = fixture('iana-dns.json');
const GOOGLE_COM = fixture('com-google.json');
const CIRA_CA = fixture('ca-cira.json');
const CA_NOT_FOUND = fixture('ca-not-found.json');

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const NOW = Date.parse('2026-10-23T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

type Route = { status: number; body?: unknown } | 'network-error';

/** A fetch that answers from a URL -> response table and records every call */
function fakeFetch(routes: Record<string, Route>) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const route = routes[url];
    if (!route || route === 'network-error') throw new TypeError(`fetch failed: ${url}`);
    void init;
    return new Response(route.body === undefined ? null : JSON.stringify(route.body), {
      status: route.status,
      headers: { 'content-type': 'application/rdap+json' },
    });
  });
}

function client(routes: Record<string, Route>, whois?: (d: string) => Promise<WhoisRecord>, clock = { now: NOW }) {
  const fetch = fakeFetch({ [BOOTSTRAP_URL]: { status: 200, body: IANA }, ...routes });
  const whoisFn = vi.fn(whois ?? (async () => { throw new Error('whois not expected'); }));
  const rdap = createRdapClient({ fetch: fetch as unknown as typeof globalThis.fetch, whois: whoisFn, now: () => clock.now });
  return { rdap, fetch, whois: whoisFn, urls: () => fetch.mock.calls.map((c) => String(c[0])) };
}

describe('IANA bootstrap', () => {
  it('maps each TLD to its RDAP server', () => {
    const servers = parseBootstrap(IANA);
    expect(servers.get('com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(servers.get('ca')).toBe('https://rdap.ca.fury.ca/rdap/');
    expect(servers.size).toBeGreaterThan(1000);
  });

  it('is fetched once for many lookups', async () => {
    const { rdap, urls } = client({
      'https://rdap.verisign.com/com/v1/domain/google.com': { status: 200, body: GOOGLE_COM },
      'https://rdap.ca.fury.ca/rdap/domain/cira.ca': { status: 200, body: CIRA_CA },
    });
    await rdap.lookupDomain('google.com');
    await rdap.lookupDomain('cira.ca');
    expect(urls().filter((u) => u === BOOTSTRAP_URL)).toHaveLength(1);
  });
});

describe('lookupDomain: .com (Verisign RDAP)', () => {
  it('returns registration data in the scoring shape', async () => {
    const { rdap, fetch, whois } = client({
      'https://rdap.verisign.com/com/v1/domain/google.com': { status: 200, body: GOOGLE_COM },
    });
    const reg = await rdap.lookupDomain('Google.com.');
    expect(reg).toEqual({
      createdAt: '1997-09-15T04:00:00.000Z',
      updatedAt: '2019-09-09T15:39:04.000Z',
      expiresAt: '2028-09-14T04:00:00.000Z',
      ageDays: Math.floor((NOW - Date.parse('1997-09-15T04:00:00Z')) / DAY),
      registrar: 'MarkMonitor Inc.',
      status: [
        'client delete prohibited',
        'client transfer prohibited',
        'client update prohibited',
        'server delete prohibited',
        'server transfer prohibited',
        'server update prohibited',
      ],
      nameservers: ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'],
      source: 'rdap',
    });
    const rdapCall = fetch.mock.calls.find((c) => String(c[0]).includes('/domain/'));
    expect((rdapCall?.[1]?.headers as Record<string, string>).Accept).toBe('application/rdap+json');
    expect(whois).not.toHaveBeenCalled();
  });
});

describe('lookupDomain: .ca (CIRA RDAP)', () => {
  it('reads the registrar from the vCard and lower-cases name servers', async () => {
    const { rdap } = client({ 'https://rdap.ca.fury.ca/rdap/domain/cira.ca': { status: 200, body: CIRA_CA } });
    const reg = await rdap.lookupDomain('cira.ca');
    expect(reg).toMatchObject({
      createdAt: '1998-02-05T05:00:00.000Z',
      expiresAt: '2050-02-05T05:00:00.000Z',
      updatedAt: '2026-08-19T19:41:33.000Z',
      registrar: 'CIRA Default Registrar',
      nameservers: ['ns1.d-zone.ca', 'ns2.d-zone.ca', 'ns3.cira.ca', 'ns4.cira.ca'],
      source: 'rdap',
    });
    expect(reg?.status).toContain('server delete prohibited');
  });
});

describe('lookupDomain: not found', () => {
  it('returns null when the registry answers 404 (CIRA body), without falling back', async () => {
    const { rdap, urls, whois } = client({
      'https://rdap.ca.fury.ca/rdap/domain/osint-analyzer-test-unregistered-7f3a9c.ca': { status: 404, body: CA_NOT_FOUND },
    });
    expect(await rdap.lookupDomain('osint-analyzer-test-unregistered-7f3a9c.ca')).toBeNull();
    expect(urls().some((u) => u.startsWith('https://rdap.org/'))).toBe(false);
    expect(whois).not.toHaveBeenCalled();
  });

  it('treats an empty-body 404 (Verisign) the same way', async () => {
    const { rdap, whois } = client({ 'https://rdap.verisign.com/com/v1/domain/nope-7f3a9c.com': { status: 404 } });
    expect(await rdap.lookupDomain('nope-7f3a9c.com')).toBeNull();
    expect(whois).not.toHaveBeenCalled();
  });
});

describe('fallbacks', () => {
  it('uses rdap.org when IANA lists no RDAP server for the TLD', async () => {
    const { rdap, urls } = client({ 'https://rdap.org/domain/example.zz': { status: 200, body: CIRA_CA } });
    const reg = await rdap.lookupDomain('example.zz');
    expect(reg?.registrar).toBe('CIRA Default Registrar');
    expect(urls()).toContain('https://rdap.org/domain/example.zz');
  });

  it('uses rdap.org when the registry server errors', async () => {
    const { rdap } = client({
      'https://rdap.verisign.com/com/v1/domain/google.com': { status: 503 },
      'https://rdap.org/domain/google.com': { status: 200, body: GOOGLE_COM },
    });
    expect((await rdap.lookupDomain('google.com'))?.registrar).toBe('MarkMonitor Inc.');
  });

  it('falls back to port-43 WHOIS and parses its dates and statuses', async () => {
    const { rdap, whois } = client(
      {
        'https://rdap.verisign.com/com/v1/domain/held-example.com': 'network-error',
        'https://rdap.org/domain/held-example.com': { status: 502 },
      },
      async () => ({
        'whois.verisign-grs.com': {
          'Domain Name': 'HELD-EXAMPLE.COM',
          'Created Date': '2026-10-10T12:00:00Z',
          'Updated Date': '2026-10-11T12:00:00Z',
          'Expiry Date': '2027-10-10T12:00:00Z',
          Registrar: 'Example Registrar, Inc.',
          'Domain Status': ['clientHold https://icann.org/epp#clientHold', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited'],
          'Name Server': ['NS1.EXAMPLE.NET', 'NS2.EXAMPLE.NET'],
        },
      })
    );
    const reg = await rdap.lookupDomain('held-example.com');
    expect(whois).toHaveBeenCalledWith('held-example.com');
    expect(reg).toEqual({
      createdAt: '2026-10-10T12:00:00.000Z',
      updatedAt: '2026-10-11T12:00:00.000Z',
      expiresAt: '2027-10-10T12:00:00.000Z',
      ageDays: 12,
      registrar: 'Example Registrar, Inc.',
      status: ['client hold', 'server transfer prohibited'],
      nameservers: ['ns1.example.net', 'ns2.example.net'],
      source: 'whois',
    });
  });

  it('returns null when RDAP, rdap.org and WHOIS all fail', async () => {
    const { rdap } = client(
      { 'https://rdap.verisign.com/com/v1/domain/down.com': { status: 500 }, 'https://rdap.org/domain/down.com': 'network-error' },
      async () => {
        throw new Error('connect ETIMEDOUT');
      }
    );
    expect(await rdap.lookupDomain('down.com')).toBeNull();
  });

  it('still works when the IANA bootstrap file cannot be loaded', async () => {
    const fetch = fakeFetch({ 'https://rdap.org/domain/google.com': { status: 200, body: GOOGLE_COM } });
    const rdap = createRdapClient({ fetch: fetch as unknown as typeof globalThis.fetch, whois: vi.fn(), now: () => NOW });
    expect((await rdap.lookupDomain('google.com'))?.source).toBe('rdap');
  });
});

describe('cache', () => {
  it('keeps a result for 24 hours, then asks again', async () => {
    const clock = { now: NOW };
    const { rdap, urls } = client(
      { 'https://rdap.verisign.com/com/v1/domain/google.com': { status: 200, body: GOOGLE_COM } },
      undefined,
      clock
    );
    await rdap.lookupDomain('google.com');
    await rdap.lookupDomain('google.com');
    const lookups = () => urls().filter((u) => u.endsWith('/domain/google.com')).length;
    expect(lookups()).toBe(1);
    clock.now += 24 * 60 * 60 * 1000 + 1;
    await rdap.lookupDomain('google.com');
    expect(lookups()).toBe(2);
  });
});
