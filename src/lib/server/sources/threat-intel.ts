// Threat-intel APIs that act as blocklists in the coverage card:
// URLhaus + ThreatFox (abuse.ch Auth-Key), AlienVault OTX (key), PhishTank (no key).
import type { BlocklistSourceResult } from '@/types';

const TIMEOUT_MS = 8000;

type SourceStatus = Pick<BlocklistSourceResult, 'status' | 'detail'>;

function failed(error: unknown, source: string): SourceStatus {
  console.warn(`${source} unavailable:`, error instanceof Error ? error.message : error);
  return { status: 'error', detail: error instanceof Error && error.name === 'TimeoutError' ? 'timed out' : 'request failed' };
}

/** URLhaus: malware distribution URLs hosted on an IP or domain */
export async function checkUrlhausHost(host: string, authKey: string): Promise<SourceStatus> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Auth-Key': authKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ host }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 401) return { status: 'error', detail: 'abuse.ch rejected the Auth-Key' };
    if (!response.ok) return { status: 'error', detail: `HTTP ${response.status}` };
    const data = await response.json();
    if (data.query_status === 'no_results') return { status: 'clean' };
    if (data.query_status !== 'ok') return { status: 'error', detail: data.query_status };
    const urls: { url_status?: string }[] = data.urls ?? [];
    const online = urls.filter((u) => u.url_status === 'online').length;
    return { status: 'listed', detail: `${data.url_count ?? urls.length} malware URL(s), ${online} online` };
  } catch (error) {
    return failed(error, 'URLhaus');
  }
}

/** ThreatFox: IOCs (C2 servers, payload hosts). IPs are stored as ip:port. */
export async function checkThreatFox(target: string, authKey: string): Promise<SourceStatus> {
  try {
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': authKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: target, exact_match: false }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 401) return { status: 'error', detail: 'abuse.ch rejected the Auth-Key' };
    if (!response.ok) return { status: 'error', detail: `HTTP ${response.status}` };
    const data = await response.json();
    if (data.query_status === 'no_result') return { status: 'clean' };
    if (data.query_status !== 'ok') return { status: 'error', detail: data.query_status };

    // Non-exact search is a substring match: keep only IOCs that really are this target
    const iocs: { ioc: string; malware_printable?: string; threat_type?: string }[] = data.data ?? [];
    const matches = iocs.filter(({ ioc }) => {
      if (ioc === target || ioc.startsWith(`${target}:`)) return true;
      try {
        return new URL(ioc).hostname === target;
      } catch {
        return false;
      }
    });
    if (matches.length === 0) return { status: 'clean' };
    const malware = Array.from(new Set(matches.map((m) => m.malware_printable).filter(Boolean))).slice(0, 3);
    return { status: 'listed', detail: `${matches.length} IOC(s)${malware.length ? `: ${malware.join(', ')}` : ''}` };
  } catch (error) {
    return failed(error, 'ThreatFox');
  }
}

/** AlienVault OTX: number of community pulses that reference the indicator */
export async function checkOtx(
  kind: 'IPv4' | 'IPv6' | 'domain',
  value: string,
  apiKey: string
): Promise<SourceStatus> {
  try {
    const response = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/${kind}/${encodeURIComponent(value)}/general`,
      { headers: { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) }
    );
    if (response.status === 403) return { status: 'error', detail: 'OTX rejected the API key' };
    if (!response.ok) return { status: 'error', detail: `HTTP ${response.status}` };
    const data = await response.json();
    const pulses: number = data.pulse_info?.count ?? 0;
    // Popular domains show up in many pulses as context; OTX marks those as whitelisted
    const whitelisted: { name?: string }[] = data.validation ?? [];
    if (whitelisted.length > 0) {
      return { status: 'clean', detail: `whitelisted by OTX (${whitelisted[0].name ?? 'validation'}), ${pulses} pulse(s)` };
    }
    return pulses > 0 ? { status: 'listed', detail: `referenced in ${pulses} pulse(s)` } : { status: 'clean' };
  } catch (error) {
    return failed(error, 'OTX');
  }
}

/**
 * PhishTank checks exact URLs, so this only catches phishing hosted at the
 * domain root. New PhishTank registrations are closed, so it runs without an
 * app key (250 requests / 5 minutes per server IP).
 */
export async function checkPhishTank(domain: string): Promise<SourceStatus> {
  const check = async (url: string) => {
    const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'User-Agent': 'phishtank/osint-analyzer', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url, format: 'json' }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 509) throw new Error('rate limited');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    return data.results?.in_database && data.results?.valid !== false ? (data.results.phish_id as number) : null;
  };
  try {
    const ids = await Promise.all([check(`http://${domain}/`), check(`https://${domain}/`)]);
    const id = ids.find((x) => x !== null);
    return id ? { status: 'listed', detail: `verified phish #${id}` } : { status: 'clean', detail: 'domain root URL only' };
  } catch (error) {
    return failed(error, 'PhishTank');
  }
}
