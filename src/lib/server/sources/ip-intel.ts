// IP reputation sources added for IP analysis. AbuseIPDB and VirusTotal live
// in lib/osint-apis.ts (shared with domain analysis).

const TIMEOUT_MS = 8000;

export interface GreyNoiseResult {
  /** Seen mass-scanning the internet */
  noise: boolean;
  /** Known benign business service (CDN, search engine crawler, …) */
  riot: boolean;
  classification: string | null;
  name: string | null;
  lastSeen: string | null;
  link: string | null;
  found: boolean;
}

export async function checkGreyNoise(ip: string, apiKey: string): Promise<GreyNoiseResult | null> {
  try {
    const response = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers: { key: apiKey, Accept: 'application/json' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    // 404 = GreyNoise has not observed this IP
    if (response.status === 404) {
      return { noise: false, riot: false, classification: null, name: null, lastSeen: null, link: null, found: false };
    }
    if (!response.ok) {
      console.error('GreyNoise API error:', response.status);
      return null;
    }
    const data = await response.json();
    return {
      noise: !!data.noise,
      riot: !!data.riot,
      classification: data.classification ?? null,
      name: data.name && data.name !== 'unknown' ? data.name : null,
      lastSeen: data.last_seen ?? null,
      link: data.link ?? null,
      found: true,
    };
  } catch (error) {
    console.error('GreyNoise fetch error:', error);
    return null;
  }
}

export interface InternetDbResult {
  ports: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  cpes: string[];
  found: boolean;
}

/** Shodan InternetDB – free, no key required */
export async function checkInternetDB(ip: string): Promise<InternetDbResult | null> {
  try {
    const response = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 404) {
      return { ports: [], hostnames: [], tags: [], vulns: [], cpes: [], found: false };
    }
    if (!response.ok) {
      console.error('InternetDB error:', response.status);
      return null;
    }
    const data = await response.json();
    return {
      ports: data.ports ?? [],
      hostnames: data.hostnames ?? [],
      tags: data.tags ?? [],
      vulns: data.vulns ?? [],
      cpes: data.cpes ?? [],
      found: true,
    };
  } catch (error) {
    console.error('InternetDB fetch error:', error);
    return null;
  }
}
