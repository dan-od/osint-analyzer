// Real OSINT API integrations
// This file contains actual API calls to various OSINT services
// Note: DNS lookups are handled in the API route to avoid browser compatibility issues

// Types
export interface DnsResult {
  mx: Array<{ exchange: string; priority: number }>;
  txt: string[];
  ns: string[];
  a: string[];
  spf: string | null;
  dmarc: string | null;
  hasMx: boolean;
  hasSpf: boolean;
  hasDmarc: boolean;
}

export interface WhoisResult {
  domainName: string;
  registrar: string | null;
  creationDate: string | null;
  expirationDate: string | null;
  updatedDate: string | null;
  status: string[];
  nameServers: string[];
  domainAge: number | null; // in days
  isNewDomain: boolean;
}

export interface AbuseIPDBResult {
  ipAddress: string;
  isPublic: boolean;
  abuseConfidenceScore: number;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  totalReports: number;
  lastReportedAt: string | null;
  isWhitelisted: boolean;
}

export interface EmailRepResult {
  email: string;
  reputation: 'high' | 'medium' | 'low' | 'none';
  suspicious: boolean;
  references: number;
  details: {
    blacklisted: boolean;
    maliciousActivity: boolean;
    credentialsLeaked: boolean;
    dataBreach: boolean;
    firstSeen: string | null;
    lastSeen: string | null;
    domainExists: boolean;
    domainReputation: string;
    newDomain: boolean;
    daysSinceDomainCreation: number;
    suspiciousTld: boolean;
    spam: boolean;
    freeProvider: boolean;
    disposable: boolean;
    deliverable: boolean;
    validMx: boolean;
    spoofable: boolean;
    spfStrict: boolean;
    dmarcEnforced: boolean;
    profiles: string[];
  };
}

export interface PhoneResult {
  valid: boolean;
  number: string;
  localFormat: string;
  internationalFormat: string;
  countryPrefix: string;
  countryCode: string;
  countryName: string;
  location: string;
  carrier: string;
  lineType: string | null;
}

export interface CryptoResult {
  address: string;
  network: 'bitcoin' | 'ethereum';
  balance: string;
  totalReceived: string;
  totalSent: string;
  txCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  isValid: boolean;
}

export interface VirusTotalResult {
  resource: string;
  positives: number;
  total: number;
  scanDate: string | null;
  permalink: string | null;
  categories: string[];
  isClean: boolean;
  /** IP lookups only */
  country?: string | null;
  asOwner?: string | null;
  /** VirusTotal community reputation score */
  reputation?: number | null;
}

export interface GoogleSafeBrowsingResult {
  isMalicious: boolean;
  threats: string[];
  platformTypes: string[];
  threatEntryTypes: string[];
}

export interface PhishStatsResult {
  found: boolean;
  url: string;
  phishScore: number;
  dateAdded: string | null;
  ipAddress: string | null;
}

export interface URLScanResult {
  uuid: string;
  url: string;
  domain: string;
  malicious: boolean;
  score: number;
  categories: string[];
  brands: string[];
}

export interface IPQualityScoreResult {
  success: boolean;
  fraudScore: number;
  valid: boolean;
  disposable: boolean;
  honeypot: boolean;
  recentAbuse: boolean;
  leaked: boolean;
  spamTrap: boolean;
}

// ============================================
// DNS LOOKUPS (Using Google DNS-over-HTTPS - No API key required)
// ============================================

export async function performDnsLookup(domain: string): Promise<DnsResult> {
  const result: DnsResult = {
    mx: [],
    txt: [],
    ns: [],
    a: [],
    spf: null,
    dmarc: null,
    hasMx: false,
    hasSpf: false,
    hasDmarc: false,
  };

  try {
    // Use Google's DNS-over-HTTPS API
    const dnsApiBase = 'https://dns.google/resolve';

    // A Records
    try {
      const aResponse = await fetch(`${dnsApiBase}?name=${encodeURIComponent(domain)}&type=A`);
      const aData = await aResponse.json();
      if (aData.Answer) {
        result.a = aData.Answer.filter((r: { type: number }) => r.type === 1).map((r: { data: string }) => r.data);
      }
    } catch {
      // No A records
    }

    // MX Records
    try {
      const mxResponse = await fetch(`${dnsApiBase}?name=${encodeURIComponent(domain)}&type=MX`);
      const mxData = await mxResponse.json();
      if (mxData.Answer) {
        result.mx = mxData.Answer
          .filter((r: { type: number }) => r.type === 15)
          .map((r: { data: string }) => {
            const parts = r.data.split(' ');
            return {
              priority: parseInt(parts[0]) || 0,
              exchange: parts[1]?.replace(/\.$/, '') || ''
            };
          })
          .sort((a: { priority: number }, b: { priority: number }) => a.priority - b.priority);
        result.hasMx = result.mx.length > 0;
      }
    } catch {
      // No MX records
    }

    // TXT Records (includes SPF)
    try {
      const txtResponse = await fetch(`${dnsApiBase}?name=${encodeURIComponent(domain)}&type=TXT`);
      const txtData = await txtResponse.json();
      if (txtData.Answer) {
        result.txt = txtData.Answer
          .filter((r: { type: number }) => r.type === 16)
          .map((r: { data: string }) => r.data.replace(/"/g, ''));
        
        // Find SPF record
        const spfRecord = result.txt.find(r => r.startsWith('v=spf1'));
        if (spfRecord) {
          result.spf = spfRecord;
          result.hasSpf = true;
        }
      }
    } catch {
      // No TXT records
    }

    // DMARC Record
    try {
      const dmarcResponse = await fetch(`${dnsApiBase}?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`);
      const dmarcData = await dmarcResponse.json();
      if (dmarcData.Answer) {
        const dmarcRecord = dmarcData.Answer
          .filter((r: { type: number }) => r.type === 16)
          .map((r: { data: string }) => r.data.replace(/"/g, ''))
          .find((r: string) => r.startsWith('v=DMARC1'));
        if (dmarcRecord) {
          result.dmarc = dmarcRecord;
          result.hasDmarc = true;
        }
      }
    } catch {
      // No DMARC record
    }

    // NS Records
    try {
      const nsResponse = await fetch(`${dnsApiBase}?name=${encodeURIComponent(domain)}&type=NS`);
      const nsData = await nsResponse.json();
      if (nsData.Answer) {
        result.ns = nsData.Answer
          .filter((r: { type: number }) => r.type === 2)
          .map((r: { data: string }) => r.data.replace(/\.$/, ''));
      }
    } catch {
      // No NS records
    }

  } catch (error) {
    console.error('DNS lookup error:', error);
  }

  return result;
}

// ============================================
// ABUSEIPDB API
// ============================================

// The caller resolves the key (user key → server key → skip), see lib/server/keys/resolver.ts
export async function checkAbuseIPDB(ip: string, apiKey: string): Promise<AbuseIPDBResult | null> {
  if (!apiKey) return null;

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      {
        headers: {
          'Key': apiKey,
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('AbuseIPDB API error:', response.status);
      return null;
    }

    const data = await response.json();
    const result = data.data;

    return {
      ipAddress: result.ipAddress,
      isPublic: result.isPublic,
      abuseConfidenceScore: result.abuseConfidenceScore,
      countryCode: result.countryCode,
      usageType: result.usageType,
      isp: result.isp,
      domain: result.domain,
      totalReports: result.totalReports,
      lastReportedAt: result.lastReportedAt,
      isWhitelisted: result.isWhitelisted || false,
    };
  } catch (error) {
    console.error('AbuseIPDB fetch error:', error);
    return null;
  }
}

// ============================================
// EMAILREP.IO API
// ============================================

export async function checkEmailRep(email: string): Promise<EmailRepResult | null> {
  const apiKey = process.env.EMAILREP_API_KEY;
  
  try {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'OSINT-Analyzer/1.0',
    };
    
    if (apiKey) {
      headers['Key'] = apiKey;
    }

    const response = await fetch(
      `https://emailrep.io/${encodeURIComponent(email)}`,
      { headers }
    );

    if (!response.ok) {
      console.error('EmailRep API error:', response.status);
      return null;
    }

    const data = await response.json();

    return {
      email: data.email,
      reputation: data.reputation,
      suspicious: data.suspicious,
      references: data.references,
      details: {
        blacklisted: data.details?.blacklisted || false,
        maliciousActivity: data.details?.malicious_activity || false,
        credentialsLeaked: data.details?.credentials_leaked || false,
        dataBreach: data.details?.data_breach || false,
        firstSeen: data.details?.first_seen || null,
        lastSeen: data.details?.last_seen || null,
        domainExists: data.details?.domain_exists || false,
        domainReputation: data.details?.domain_reputation || 'unknown',
        newDomain: data.details?.new_domain || false,
        daysSinceDomainCreation: data.details?.days_since_domain_creation || 0,
        suspiciousTld: data.details?.suspicious_tld || false,
        spam: data.details?.spam || false,
        freeProvider: data.details?.free_provider || false,
        disposable: data.details?.disposable || false,
        deliverable: data.details?.deliverable || false,
        validMx: data.details?.valid_mx || false,
        spoofable: data.details?.spoofable || false,
        spfStrict: data.details?.spf_strict || false,
        dmarcEnforced: data.details?.dmarc_enforced || false,
        profiles: data.details?.profiles || [],
      },
    };
  } catch (error) {
    console.error('EmailRep fetch error:', error);
    return null;
  }
}

// ============================================
// WHOISXML API
// ============================================

export async function checkWhois(domain: string): Promise<WhoisResult | null> {
  const apiKey = process.env.WHOISXML_API_KEY;
  
  if (!apiKey) {
    console.log('WhoisXML API key not configured');
    return null;
  }

  try {
    const response = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('WhoisXML API error:', response.status);
      return null;
    }

    const data = await response.json();
    const record = data.WhoisRecord;

    if (!record) return null;

    const creationDate = record.createdDate || record.registryData?.createdDate;
    const domainAge = creationDate 
      ? Math.floor((Date.now() - new Date(creationDate).getTime()) / (1000 * 60 * 60 * 24))
      : null;

    return {
      domainName: record.domainName,
      registrar: record.registrarName || record.registryData?.registrarName || null,
      creationDate: creationDate || null,
      expirationDate: record.expiresDate || record.registryData?.expiresDate || null,
      updatedDate: record.updatedDate || record.registryData?.updatedDate || null,
      status: record.status ? (Array.isArray(record.status) ? record.status : [record.status]) : [],
      nameServers: record.nameServers?.hostNames || [],
      domainAge,
      isNewDomain: domainAge !== null && domainAge < 365,
    };
  } catch (error) {
    console.error('WhoisXML fetch error:', error);
    return null;
  }
}

// ============================================
// NUMVERIFY API (Phone)
// ============================================

export async function checkPhone(phone: string): Promise<PhoneResult | null> {
  const apiKey = process.env.NUMVERIFY_API_KEY;
  
  if (!apiKey) {
    console.log('NumVerify API key not configured');
    return null;
  }

  try {
    // Clean phone number
    const cleanPhone = phone.replace(/[^0-9+]/g, '');
    
    const response = await fetch(
      `http://apilayer.net/api/validate?access_key=${apiKey}&number=${encodeURIComponent(cleanPhone)}&format=1`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('NumVerify API error:', response.status);
      return null;
    }

    const data = await response.json();

    if (!data.valid && !data.number) {
      return null;
    }

    return {
      valid: data.valid || false,
      number: data.number || cleanPhone,
      localFormat: data.local_format || '',
      internationalFormat: data.international_format || '',
      countryPrefix: data.country_prefix || '',
      countryCode: data.country_code || '',
      countryName: data.country_name || '',
      location: data.location || '',
      carrier: data.carrier || '',
      lineType: data.line_type || null,
    };
  } catch (error) {
    console.error('NumVerify fetch error:', error);
    return null;
  }
}

// ============================================
// VIRUSTOTAL API
// ============================================

export async function checkVirusTotal(
  resource: string,
  type: 'domain' | 'url' | 'ip',
  apiKey: string
): Promise<VirusTotalResult | null> {
  if (!apiKey) return null;

  try {
    let endpoint = '';
    
    if (type === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(resource)}`;
    } else if (type === 'ip') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(resource)}`;
    } else {
      // URL needs to be base64 encoded
      const urlId = Buffer.from(resource).toString('base64').replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    }

    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      console.error('VirusTotal API error:', response.status);
      return null;
    }

    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const positives = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a: number, b) => a + (b as number), 0) as number;

    return {
      resource,
      positives,
      total,
      scanDate: data.data?.attributes?.last_analysis_date 
        ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString()
        : null,
      permalink: data.data?.links?.self || null,
      categories: Object.keys(data.data?.attributes?.categories || {}),
      isClean: positives === 0,
      country: data.data?.attributes?.country || null,
      asOwner: data.data?.attributes?.as_owner || null,
      reputation: typeof data.data?.attributes?.reputation === 'number' ? data.data.attributes.reputation : null,
    };
  } catch (error) {
    console.error('VirusTotal fetch error:', error);
    return null;
  }
}

// ============================================
// BLOCKCHAIN APIs (Bitcoin & Ethereum)
// ============================================

export async function checkBitcoinWallet(address: string): Promise<CryptoResult | null> {
  try {
    const response = await fetch(
      `https://blockchain.info/rawaddr/${encodeURIComponent(address)}?limit=1`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('Blockchain.info API error:', response.status);
      return null;
    }

    const data = await response.json();

    return {
      address: data.address,
      network: 'bitcoin',
      balance: (data.final_balance / 100000000).toFixed(8) + ' BTC',
      totalReceived: (data.total_received / 100000000).toFixed(8) + ' BTC',
      totalSent: (data.total_sent / 100000000).toFixed(8) + ' BTC',
      txCount: data.n_tx,
      firstSeen: data.txs?.[0]?.time 
        ? new Date(data.txs[0].time * 1000).toISOString()
        : null,
      lastSeen: data.txs?.[data.txs.length - 1]?.time
        ? new Date(data.txs[data.txs.length - 1].time * 1000).toISOString()
        : null,
      isValid: true,
    };
  } catch (error) {
    console.error('Blockchain.info fetch error:', error);
    return null;
  }
}

export async function checkEthereumWallet(address: string): Promise<CryptoResult | null> {
  const apiKey = process.env.ETHERSCAN_API_KEY;
  
  try {
    // Get balance
    const balanceUrl = apiKey
      ? `https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest&apikey=${apiKey}`
      : `https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest`;
    
    const balanceResponse = await fetch(balanceUrl);
    const balanceData = await balanceResponse.json();

    // Get transaction count
    const txUrl = apiKey
      ? `https://api.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=1&sort=asc&apikey=${apiKey}`
      : `https://api.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=1&sort=asc`;
    
    const txResponse = await fetch(txUrl);
    const txData = await txResponse.json();

    if (balanceData.status !== '1' && balanceData.message !== 'OK') {
      return null;
    }

    const balanceWei = BigInt(balanceData.result || '0');
    const balanceEth = Number(balanceWei) / 1e18;

    return {
      address,
      network: 'ethereum',
      balance: balanceEth.toFixed(6) + ' ETH',
      totalReceived: 'N/A',
      totalSent: 'N/A',
      txCount: txData.result?.length || 0,
      firstSeen: txData.result?.[0]?.timeStamp
        ? new Date(parseInt(txData.result[0].timeStamp) * 1000).toISOString()
        : null,
      lastSeen: null,
      isValid: true,
    };
  } catch (error) {
    console.error('Etherscan fetch error:', error);
    return null;
  }
}

// ============================================
// SCAM DATABASE CHECK (ChainAbuse - No API needed for basic)
// ============================================

export async function checkScamDatabase(_query: string, _type: 'crypto' | 'domain' | 'email'): Promise<{ isKnownScam: boolean; reports: number; source: string } | null> {
  // This is a placeholder for scam database integration
  // In production, you would integrate with services like:
  // - ChainAbuse API
  // - ScamAdviser
  // - PhishTank
  // - OpenPhish
  
  // For now, return null to indicate no scam database check performed
  return null;
}

// ============================================
// HUNTER.IO API (Email Verification)
// ============================================

export async function verifyEmailHunter(email: string, apiKey: string): Promise<{
  result: string;
  score: number;
  regexp: boolean;
  gibberish: boolean;
  disposable: boolean;
  webmail: boolean;
  mxRecords: boolean;
  smtpServer: boolean;
  smtpCheck: boolean;
  acceptAll: boolean;
  block: boolean;
} | null> {
  if (!apiKey) return null;

  try {
    const response = await fetch(
      `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${apiKey}`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('Hunter.io API error:', response.status);
      return null;
    }

    const data = await response.json();
    const result = data.data;

    return {
      result: result.result,
      score: result.score,
      regexp: result.regexp,
      gibberish: result.gibberish,
      disposable: result.disposable,
      webmail: result.webmail,
      mxRecords: result.mx_records,
      smtpServer: result.smtp_server,
      smtpCheck: result.smtp_check,
      acceptAll: result.accept_all,
      block: result.block,
    };
  } catch (error) {
    console.error('Hunter.io fetch error:', error);
    return null;
  }
}

// ============================================
// GOOGLE SAFE BROWSING API
// ============================================

export async function checkGoogleSafeBrowsing(url: string): Promise<GoogleSafeBrowsingResult | null> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  
  if (!apiKey) {
    console.log('Google Safe Browsing API key not configured');
    return null;
  }

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client: {
            clientId: 'osint-analyzer',
            clientVersion: '1.0.0'
          },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
              'THREAT_TYPE_UNSPECIFIED'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );

    if (!response.ok) {
      console.error('Google Safe Browsing API error:', response.status);
      return null;
    }

    const data = await response.json();
    
    if (data.matches && data.matches.length > 0) {
      return {
        isMalicious: true,
        threats: data.matches.map((m: { threatType: string }) => m.threatType),
        platformTypes: data.matches.map((m: { platformType: string }) => m.platformType),
        threatEntryTypes: data.matches.map((m: { threatEntryType: string }) => m.threatEntryType),
      };
    }

    return {
      isMalicious: false,
      threats: [],
      platformTypes: [],
      threatEntryTypes: [],
    };
  } catch (error) {
    console.error('Google Safe Browsing fetch error:', error);
    return null;
  }
}

// ============================================
// PHISHSTATS API (Free - No API key required)
// ============================================

export async function checkPhishStats(url: string): Promise<PhishStatsResult | null> {
  try {
    // PhishStats has a public API that can be queried
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    
    const response = await fetch(
      `https://phishstats.info/api/phishing?_where=(url,like,~${encodeURIComponent(domain)}~)&_sort=-date`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      console.error('PhishStats API error:', response.status);
      return null;
    }

    const data = await response.json();
    
    if (data && data.length > 0) {
      const match = data[0];
      return {
        found: true,
        url: match.url || url,
        phishScore: match.score || 0,
        dateAdded: match.date || null,
        ipAddress: match.ip || null,
      };
    }

    return {
      found: false,
      url: url,
      phishScore: 0,
      dateAdded: null,
      ipAddress: null,
    };
  } catch (error) {
    console.error('PhishStats fetch error:', error);
    return null;
  }
}

// ============================================
// URLSCAN.IO API
// ============================================

export async function checkURLScan(url: string): Promise<URLScanResult | null> {
  const apiKey = process.env.URLSCAN_API_KEY;
  
  try {
    // Search for existing scans of this URL
    const searchUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(url.replace(/^https?:\/\//, '').split('/')[0])}`;
    
    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };
    
    if (apiKey) {
      headers['API-Key'] = apiKey;
    }

    const response = await fetch(searchUrl, { headers });

    if (!response.ok) {
      console.error('URLScan API error:', response.status);
      return null;
    }

    const data = await response.json();
    
    if (data.results && data.results.length > 0) {
      const result = data.results[0];
      return {
        uuid: result.task?.uuid || '',
        url: result.task?.url || url,
        domain: result.task?.domain || '',
        malicious: result.verdicts?.overall?.malicious || false,
        score: result.verdicts?.overall?.score || 0,
        categories: result.verdicts?.overall?.categories || [],
        brands: result.verdicts?.overall?.brands || [],
      };
    }

    return null;
  } catch (error) {
    console.error('URLScan fetch error:', error);
    return null;
  }
}

// ============================================
// OPENPHISH CHECK (Free - No API key required)
// ============================================

// The feed changes every few hours; keep it in memory instead of downloading it per lookup
let openPhishCache: { urls: string[]; fetchedAt: number } | null = null;
const OPENPHISH_TTL_MS = 60 * 60 * 1000;

export async function checkOpenPhish(domain: string): Promise<{ found: boolean; url?: string } | null> {
  try {
    if (!openPhishCache || Date.now() - openPhishCache.fetchedAt > OPENPHISH_TTL_MS) {
      // OpenPhish provides a free feed that we can check
      const response = await fetch('https://openphish.com/feed.txt', {
        headers: {
          'Accept': 'text/plain',
        },
      });

      if (!response.ok) {
        console.error('OpenPhish API error:', response.status);
        return null;
      }

      openPhishCache = { urls: (await response.text()).split('\n'), fetchedAt: Date.now() };
    }

    const urls = openPhishCache.urls;

    const matchingUrl = urls.find(url => url.includes(domain));
    
    return {
      found: !!matchingUrl,
      url: matchingUrl || undefined,
    };
  } catch (error) {
    console.error('OpenPhish fetch error:', error);
    return null;
  }
}

// ============================================
// SPAMHAUS DBL CHECK (Domain Block List)
// ============================================

export async function checkSpamhausDBL(domain: string): Promise<{ listed: boolean; reason?: string } | null> {
  try {
    // Use DNS lookup to check Spamhaus DBL
    const dnsApiBase = 'https://dns.google/resolve';
    const response = await fetch(`${dnsApiBase}?name=${domain}.dbl.spamhaus.org&type=A`);
    
    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      const ip = data.Answer[0].data;
      // 127.255.255.x = query refused (e.g. public resolver), not a listing
      if (ip.startsWith('127.255.255.')) return null;

      // Decode Spamhaus return codes
      const reasons: Record<string, string> = {
        '127.0.1.2': 'Spam domain',
        '127.0.1.3': 'Spam domain (redirector)',
        '127.0.1.4': 'Phishing domain',
        '127.0.1.5': 'Malware domain',
        '127.0.1.6': 'Botnet C&C domain',
        '127.0.1.102': 'Abused legit spam',
        '127.0.1.103': 'Abused legit spammed redirector',
        '127.0.1.104': 'Abused legit phish',
        '127.0.1.105': 'Abused legit malware',
        '127.0.1.106': 'Abused legit botnet C&C',
      };

      return {
        listed: true,
        reason: reasons[ip] || `Listed (${ip})`,
      };
    }

    return { listed: false };
  } catch (error) {
    console.error('Spamhaus DBL check error:', error);
    return null;
  }
}

// ============================================
// SURBL CHECK (Spam URI Realtime Blocklists)
// ============================================

export async function checkSURBL(domain: string): Promise<{ listed: boolean; lists: string[] } | null> {
  try {
    const dnsApiBase = 'https://dns.google/resolve';
    const response = await fetch(`${dnsApiBase}?name=${domain}.multi.surbl.org&type=A`);
    
    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      const ip = data.Answer[0].data;
      const lastOctet = parseInt(ip.split('.')[3]);
      // 127.0.0.1 = SURBL refused this resolver
      if (lastOctet === 1) return null;

      const lists: string[] = [];
      if (lastOctet & 1) lists.push('SC (SpamCop)');
      if (lastOctet & 2) lists.push('WS (sa-blacklist)');
      if (lastOctet & 4) lists.push('PH (Phishing)');
      if (lastOctet & 8) lists.push('MW (Malware)');
      if (lastOctet & 16) lists.push('AB (AbuseButler)');
      if (lastOctet & 32) lists.push('JP (JWSpamSpy)');
      if (lastOctet & 64) lists.push('CR (Cracked/compromised)');

      return {
        listed: true,
        lists,
      };
    }

    return { listed: false, lists: [] };
  } catch (error) {
    console.error('SURBL check error:', error);
    return null;
  }
}

// ============================================
// CHECK IP AGAINST MULTIPLE BLACKLISTS
// ============================================

export async function checkIPBlacklists(ip: string): Promise<{ 
  listed: boolean; 
  blacklists: string[];
  totalChecked: number;
} | null> {
  const blacklistServers = [
    { name: 'Spamhaus ZEN', server: 'zen.spamhaus.org' },
    { name: 'Barracuda', server: 'b.barracudacentral.org' },
    { name: 'SpamCop', server: 'bl.spamcop.net' },
    { name: 'SORBS', server: 'dnsbl.sorbs.net' },
    { name: 'UCEPROTECT', server: 'dnsbl-1.uceprotect.net' },
  ];

  const reversedIp = ip.split('.').reverse().join('.');
  const dnsApiBase = 'https://dns.google/resolve';
  const listedOn: string[] = [];

  try {
    const checks = await Promise.allSettled(
      blacklistServers.map(async (bl) => {
        const response = await fetch(`${dnsApiBase}?name=${reversedIp}.${bl.server}&type=A`);
        if (response.ok) {
          const data = await response.json();
          const answers: string[] = (data.Answer ?? []).map((a: { data: string }) => a.data);
          if (answers.length > 0 && !answers.some((a) => a.startsWith('127.255.255.'))) {
            return bl.name;
          }
        }
        return null;
      })
    );

    checks.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        listedOn.push(result.value);
      }
    });

    return {
      listed: listedOn.length > 0,
      blacklists: listedOn,
      totalChecked: blacklistServers.length,
    };
  } catch (error) {
    console.error('IP blacklist check error:', error);
    return null;
  }
}

// ============================================
// DISPOSABLE EMAIL DOMAINS CHECK
// ============================================

const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
  'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'getnada.com',
  'maildrop.cc', 'mohmal.com', 'tempail.com', 'tmpmail.org', 'tmpmail.net',
  'dispostable.com', 'mailnesia.com', 'trashmail.com', 'sharklasers.com',
  'yopmail.com', 'getairmail.com', 'spamgourmet.com', 'mintemail.com',
  'emailondeck.com', 'discard.email', 'burnermail.io', 'inboxalias.com',
  'tempr.email', 'anonymmail.net', 'mailcatch.com', 'jetable.org',
  'emailsensei.com', 'burnbox.io', 'incognitomail.org', 'fakemailgenerator.com'
]);

export function isDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  return domain ? DISPOSABLE_DOMAINS.has(domain) : false;
}

// ============================================
// SUSPICIOUS TLD CHECK
// ============================================

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'online', 'site',
  'website', 'space', 'tech', 'store', 'click', 'link', 'work', 'date',
  'download', 'stream', 'racing', 'win', 'review', 'accountant', 'cricket',
  'faith', 'loan', 'men', 'party', 'science', 'trade', 'webcam', 'bid',
  'buzz', 'gdn', 'kim', 'ren', 'wang', 'asia', 'rocks', 'world'
]);

export function hasSuspiciousTLD(domain: string): boolean {
  const tld = domain.split('.').pop()?.toLowerCase();
  return tld ? SUSPICIOUS_TLDS.has(tld) : false;
}

// ============================================
// TYPOSQUATTING CHECK
// ============================================

const POPULAR_DOMAINS = [
  'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'paypal',
  'instagram', 'twitter', 'linkedin', 'youtube', 'whatsapp', 'github', 'yahoo',
  'outlook', 'office', 'dropbox', 'spotify', 'tiktok', 'snapchat', 'pinterest',
  'reddit', 'tumblr', 'wordpress', 'blogger', 'medium', 'twitch', 'discord',
  'zoom', 'webex', 'slack', 'teams', 'skype', 'telegram', 'signal', 'adobe',
  'salesforce', 'oracle', 'ibm', 'cisco', 'vmware', 'nvidia', 'intel', 'amd',
  'walmart', 'target', 'bestbuy', 'costco', 'ebay', 'aliexpress', 'shopify'
];

export function checkTyposquatting(domain: string): { 
  isTyposquat: boolean; 
  targetBrand?: string;
  similarity?: number;
} {
  const domainLower = domain.toLowerCase().split('.')[0];
  
  for (const brand of POPULAR_DOMAINS) {
    // Check for common typosquatting patterns
    const patterns = [
      brand.replace(/o/g, '0'),  // google -> g00gle
      brand.replace(/i/g, '1'),  // microsoft -> m1crosoft
      brand.replace(/e/g, '3'),  // facebook -> fac3book
      brand.replace(/a/g, '4'),  // amazon -> 4mazon
      brand.replace(/s/g, '5'),  // microsoft -> micro5oft
      brand + 's',               // google -> googles
      brand + 'login',           // paypal -> paypallogin
      brand + 'security',        // apple -> applesecurity
      brand + 'verify',          // amazon -> amazonverify
      brand + 'account',         // netflix -> netflixaccount
      brand + '-login',
      brand + '-verify',
      brand + '-account',
      'login' + brand,
      'secure' + brand,
      'my' + brand,
    ];

    // Check direct patterns
    if (patterns.some(p => domainLower.includes(p))) {
      return { isTyposquat: true, targetBrand: brand };
    }

    // Check Levenshtein distance for close matches
    if (domainLower.includes(brand.substring(0, 4)) && domainLower !== brand) {
      const similarity = calculateSimilarity(domainLower, brand);
      if (similarity > 0.7 && similarity < 1) {
        return { isTyposquat: true, targetBrand: brand, similarity };
      }
    }
  }

  return { isTyposquat: false };
}

function calculateSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;
  
  if (longer.length === 0) return 1.0;
  
  const costs: number[] = [];
  for (let i = 0; i <= shorter.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= longer.length; j++) {
      if (i === 0) {
        costs[j] = j;
      } else if (j > 0) {
        let newValue = costs[j - 1];
        if (shorter[i - 1] !== longer[j - 1]) {
          newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
        }
        costs[j - 1] = lastValue;
        lastValue = newValue;
      }
    }
    if (i > 0) costs[longer.length] = lastValue;
  }
  
  return (longer.length - costs[longer.length]) / longer.length;
}

// ============================================
// CRYPTO SCAM DETECTION APIs
// ============================================

export interface ChainAbuseResult {
  found: boolean;
  reports: number;
  categories: string[];
  lastReported: string | null;
  riskScore: number;
}

export interface CryptoScamDBResult {
  isScam: boolean;
  source: string;
  category?: string;
  description?: string;
}

// ChainAbuse.com lookup
export async function checkChainAbuse(address: string): Promise<ChainAbuseResult | null> {
  try {
    // ChainAbuse has a public search - we can scrape/check their API
    // For now, using their public endpoint pattern
    const response = await fetch(
      `https://www.chainabuse.com/api/v0/report?address=${encodeURIComponent(address)}`,
      {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'OSINT-Analyzer/1.0',
        },
      }
    );

    if (!response.ok) {
      // Try alternative approach - check if address appears in their database
      return await checkChainAbuseAlternative(address);
    }

    const data = await response.json();
    
    if (data && data.reports && data.reports.length > 0) {
      return {
        found: true,
        reports: data.reports.length,
        categories: Array.from(new Set(data.reports.map((r: { category: string }) => r.category))),
        lastReported: data.reports[0]?.createdAt || null,
        riskScore: Math.min(100, data.reports.length * 20),
      };
    }

    return {
      found: false,
      reports: 0,
      categories: [],
      lastReported: null,
      riskScore: 0,
    };
  } catch (error) {
    console.error('ChainAbuse check error:', error);
    return await checkChainAbuseAlternative(address);
  }
}

async function checkChainAbuseAlternative(address: string): Promise<ChainAbuseResult | null> {
  try {
    // Check against known scam databases hosted on GitHub
    const scamLists = [
      'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/bitcoin-scam-addresses.txt',
    ];

    for (const listUrl of scamLists) {
      try {
        const response = await fetch(listUrl);
        if (response.ok) {
          const text = await response.text();
          if (text.toLowerCase().includes(address.toLowerCase())) {
            return {
              found: true,
              reports: 1,
              categories: ['Known Scam Address'],
              lastReported: null,
              riskScore: 80,
            };
          }
        }
      } catch {
        continue;
      }
    }

    return {
      found: false,
      reports: 0,
      categories: [],
      lastReported: null,
      riskScore: 0,
    };
  } catch (error) {
    console.error('ChainAbuse alternative check error:', error);
    return null;
  }
}

// BTC Black DNS Blacklist check
export async function checkBTCBlackDNSBL(address: string): Promise<{ listed: boolean; reason?: string } | null> {
  try {
    // BTC Black uses DNS-based lookups similar to email blacklists
    // Format: <address>.btc.black
    const dnsApiBase = 'https://dns.google/resolve';
    
    // Hash the address for lookup (BTC Black uses specific format)
    const response = await fetch(`${dnsApiBase}?name=${address}.btc.black&type=A`);
    
    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      return {
        listed: true,
        reason: 'Address found in BTC Black blacklist',
      };
    }

    return { listed: false };
  } catch (error) {
    console.error('BTC Black check error:', error);
    return null;
  }
}

// Check against known ransomware addresses (OpenSanctions/ransomwhe.re data)
export async function checkRansomwareAddresses(address: string): Promise<CryptoScamDBResult | null> {
  try {
    // Known ransomware Bitcoin addresses patterns
    const knownRansomwarePatterns = [
      // These are example patterns - in production, fetch from OpenSanctions
      { prefix: '1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX', type: 'WannaCry' },
      { prefix: '12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw', type: 'WannaCry' },
      { prefix: '13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94', type: 'WannaCry' },
      { prefix: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', type: 'Twitter Hack 2020' },
    ];

    for (const pattern of knownRansomwarePatterns) {
      if (address.toLowerCase() === pattern.prefix.toLowerCase()) {
        return {
          isScam: true,
          source: 'Ransomware Database',
          category: pattern.type,
          description: `Known ${pattern.type} ransomware address`,
        };
      }
    }

    // Check OpenSanctions API if available
    try {
      const response = await fetch(
        `https://api.opensanctions.org/search/default?q=${encodeURIComponent(address)}&schema=CryptoWallet`,
        {
          headers: {
            'Accept': 'application/json',
          },
        }
      );

      if (response.ok) {
        const data = await response.json();
        if (data.results && data.results.length > 0) {
          return {
            isScam: true,
            source: 'OpenSanctions',
            category: 'Sanctioned Entity',
            description: data.results[0]?.caption || 'Found in sanctions database',
          };
        }
      }
    } catch {
      // OpenSanctions API not available
    }

    return { isScam: false, source: 'Ransomware Database' };
  } catch (error) {
    console.error('Ransomware address check error:', error);
    return null;
  }
}

// Check against GitHub-hosted scam databases
export async function checkGitHubScamLists(address: string): Promise<CryptoScamDBResult | null> {
  const scamListUrls = [
    {
      url: 'https://raw.githubusercontent.com/Badd-Boyz/Badd-Boyz-Bitcoin-Scammers/main/bitcoin-addresses.txt',
      name: 'Badd-Boyz Bitcoin Scammers'
    },
    {
      url: 'https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/addresses.json',
      name: 'CryptoScamDB'
    },
  ];

  try {
    for (const list of scamListUrls) {
      try {
        const response = await fetch(list.url, {
          headers: { 'Accept': 'text/plain,application/json' },
        });

        if (response.ok) {
          const text = await response.text();
          
          // Check if it's JSON
          if (list.url.endsWith('.json')) {
            try {
              const data = JSON.parse(text);
              // Handle different JSON formats
              const addresses = Array.isArray(data) ? data : Object.keys(data);
              if (addresses.some((a: string) => a.toLowerCase() === address.toLowerCase())) {
                return {
                  isScam: true,
                  source: list.name,
                  category: 'Known Scam',
                  description: `Address found in ${list.name}`,
                };
              }
            } catch {
              // Not valid JSON, treat as text
            }
          }
          
          // Text-based check
          if (text.toLowerCase().includes(address.toLowerCase())) {
            return {
              isScam: true,
              source: list.name,
              category: 'Known Scam',
              description: `Address found in ${list.name}`,
            };
          }
        }
      } catch {
        continue;
      }
    }

    return { isScam: false, source: 'GitHub Scam Lists' };
  } catch (error) {
    console.error('GitHub scam list check error:', error);
    return null;
  }
}

// Chainalysis OFAC Sanctions check (if API key available)
export async function checkChainalysisSanctions(address: string): Promise<{
  sanctioned: boolean;
  programs?: string[];
  entity?: string;
} | null> {
  const apiKey = process.env.CHAINALYSIS_API_KEY;
  
  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch(
      `https://api.chainalysis.com/api/kyt/v1/users/${encodeURIComponent(address)}/sanctions`,
      {
        headers: {
          'Token': apiKey,
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    return {
      sanctioned: data.sanctioned || false,
      programs: data.programs || [],
      entity: data.entity || undefined,
    };
  } catch (error) {
    console.error('Chainalysis sanctions check error:', error);
    return null;
  }
}

// Comprehensive crypto address risk assessment
export async function assessCryptoRisk(address: string, network: 'bitcoin' | 'ethereum'): Promise<{
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  flags: string[];
  sources: string[];
}> {
  const flags: string[] = [];
  const sources: string[] = [];
  let riskScore = 0;

  // Run all checks in parallel
  const [
    chainAbuseResult,
    btcBlackResult,
    ransomwareResult,
    githubScamResult,
    chainalysisResult,
  ] = await Promise.all([
    checkChainAbuse(address),
    network === 'bitcoin' ? checkBTCBlackDNSBL(address) : Promise.resolve(null),
    checkRansomwareAddresses(address),
    checkGitHubScamLists(address),
    checkChainalysisSanctions(address),
  ]);

  // Evaluate ChainAbuse results
  if (chainAbuseResult?.found) {
    riskScore += chainAbuseResult.riskScore;
    flags.push(`Reported ${chainAbuseResult.reports} times on ChainAbuse`);
    if (chainAbuseResult.categories.length > 0) {
      flags.push(`Categories: ${chainAbuseResult.categories.join(', ')}`);
    }
    sources.push('ChainAbuse');
  }

  // Evaluate BTC Black results
  if (btcBlackResult?.listed) {
    riskScore += 60;
    flags.push('Listed on BTC Black DNSBL');
    sources.push('BTC Black');
  }

  // Evaluate ransomware database results
  if (ransomwareResult?.isScam) {
    riskScore += 90;
    flags.push(`${ransomwareResult.category}: ${ransomwareResult.description}`);
    sources.push(ransomwareResult.source);
  }

  // Evaluate GitHub scam lists
  if (githubScamResult?.isScam) {
    riskScore += 70;
    flags.push(githubScamResult.description || 'Found in scam database');
    sources.push(githubScamResult.source);
  }

  // Evaluate Chainalysis sanctions
  if (chainalysisResult?.sanctioned) {
    riskScore += 100;
    flags.push('OFAC SANCTIONED ADDRESS');
    if (chainalysisResult.programs) {
      flags.push(`Sanctions programs: ${chainalysisResult.programs.join(', ')}`);
    }
    sources.push('Chainalysis OFAC');
  }

  // Cap risk score at 100
  riskScore = Math.min(100, riskScore);

  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 80) {
    riskLevel = 'critical';
  } else if (riskScore >= 50) {
    riskLevel = 'high';
  } else if (riskScore >= 25) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  return {
    riskLevel,
    riskScore,
    flags,
    sources,
  };
}

// ============================================
// IPQUALITYSCORE - EMAIL & PHONE VALIDATION
// ============================================

export interface IPQSEmailResult {
  valid: boolean;
  disposable: boolean;
  honeypot: boolean;
  spamTrap: boolean;
  recentAbuse: boolean;
  leaked: boolean;
  fraudScore: number;
  deliverability: string;
  smtpScore: number;
  overallScore: number;
  firstSeen: string | null;
  domainAge: number | null;
  suspicious: boolean;
  catchAll: boolean;
  genericEmail: boolean;
  commonProvider: boolean;
}

export async function checkIPQSEmail(email: string, apiKey: string): Promise<IPQSEmailResult | null> {
  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch(
      `https://ipqualityscore.com/api/json/email/${apiKey}/${encodeURIComponent(email)}?strictness=1&abuse_strictness=1`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    if (!data.success) {
      return null;
    }

    return {
      valid: data.valid || false,
      disposable: data.disposable || false,
      honeypot: data.honeypot || false,
      spamTrap: data.spam_trap_score === 'high' || data.spam_trap_score === 'medium',
      recentAbuse: data.recent_abuse || false,
      leaked: data.leaked || false,
      fraudScore: data.fraud_score || 0,
      deliverability: data.deliverability || 'unknown',
      smtpScore: data.smtp_score || 0,
      overallScore: data.overall_score || 0,
      firstSeen: data.first_seen?.human || null,
      domainAge: data.domain_age?.human ? parseInt(data.domain_age.human) : null,
      suspicious: data.suspect || false,
      catchAll: data.catch_all || false,
      genericEmail: data.generic || false,
      commonProvider: data.common || false,
    };
  } catch (error) {
    console.error('IPQS Email check error:', error);
    return null;
  }
}

export interface IPQSPhoneResult {
  valid: boolean;
  fraudScore: number;
  recentAbuse: boolean;
  voip: boolean;
  prepaid: boolean;
  risky: boolean;
  active: boolean;
  carrier: string | null;
  lineType: string | null;
  country: string | null;
  city: string | null;
  spammer: boolean;
  associated_email_addresses: number;
  leaked: boolean;
  name: string | null;
}

export async function checkIPQSPhone(phone: string, apiKey: string): Promise<IPQSPhoneResult | null> {
  if (!apiKey) {
    return null;
  }

  try {
    // Clean phone number
    const cleanPhone = phone.replace(/[^0-9+]/g, '');
    
    const response = await fetch(
      `https://ipqualityscore.com/api/json/phone/${apiKey}/${encodeURIComponent(cleanPhone)}?strictness=1`,
      {
        headers: {
          'Accept': 'application/json',
        },
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    if (!data.success) {
      return null;
    }

    return {
      valid: data.valid || false,
      fraudScore: data.fraud_score || 0,
      recentAbuse: data.recent_abuse || false,
      voip: data.VOIP || false,
      prepaid: data.prepaid || false,
      risky: data.risky || false,
      active: data.active || false,
      carrier: data.carrier || null,
      lineType: data.line_type || null,
      country: data.country || null,
      city: data.city || null,
      spammer: data.spammer || false,
      associated_email_addresses: data.associated_email_addresses?.count || 0,
      leaked: data.leaked || false,
      name: data.name || null,
    };
  } catch (error) {
    console.error('IPQS Phone check error:', error);
    return null;
  }
}

// ============================================
// HAVE I BEEN PWNED - BREACH DATABASE
// ============================================

export interface HIBPResult {
  breached: boolean;
  breachCount: number;
  breaches: {
    name: string;
    domain: string;
    breachDate: string;
    dataClasses: string[];
    isVerified: boolean;
    isSensitive: boolean;
  }[];
  pasteCount: number;
}

export async function checkHaveIBeenPwned(email: string, apiKey: string): Promise<HIBPResult | null> {
  // HIBP requires API key for breach lookups
  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'OSINT-Analyzer',
        },
      }
    );

    if (response.status === 404) {
      // No breaches found
      return {
        breached: false,
        breachCount: 0,
        breaches: [],
        pasteCount: 0,
      };
    }

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    const breaches = data.map((b: {
      Name: string;
      Domain: string;
      BreachDate: string;
      DataClasses: string[];
      IsVerified: boolean;
      IsSensitive: boolean;
    }) => ({
      name: b.Name,
      domain: b.Domain,
      breachDate: b.BreachDate,
      dataClasses: b.DataClasses || [],
      isVerified: b.IsVerified || false,
      isSensitive: b.IsSensitive || false,
    }));

    // Check pastes (separate endpoint)
    let pasteCount = 0;
    try {
      const pasteResponse = await fetch(
        `https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(email)}`,
        {
          headers: {
            'hibp-api-key': apiKey,
            'User-Agent': 'OSINT-Analyzer',
          },
        }
      );
      if (pasteResponse.ok) {
        const pastes = await pasteResponse.json();
        pasteCount = Array.isArray(pastes) ? pastes.length : 0;
      }
    } catch {
      // Paste check failed, continue without it
    }

    return {
      breached: breaches.length > 0,
      breachCount: breaches.length,
      breaches,
      pasteCount,
    };
  } catch (error) {
    console.error('HIBP check error:', error);
    return null;
  }
}

// ============================================
// PHONE SPAM DATABASES & PATTERN DETECTION
// ============================================

export interface PhoneSpamResult {
  isSpam: boolean;
  spamScore: number;
  reports: number;
  categories: string[];
  source: string;
}

// Check against known spam number patterns and databases
export async function checkPhoneSpamDatabases(phone: string): Promise<PhoneSpamResult | null> {
  const cleanPhone = phone.replace(/[^0-9]/g, '');
  
  try {
    // Check against community spam databases
    const spamPatterns = await checkSpamPatterns(cleanPhone);
    
    if (spamPatterns.isSpam) {
      return spamPatterns;
    }

    // Check if it's a premium rate number
    const premiumCheck = checkPremiumRateNumber(cleanPhone);
    if (premiumCheck.isPremium) {
      return {
        isSpam: false,
        spamScore: 40,
        reports: 0,
        categories: [`Premium Rate Number: ${premiumCheck.type}`],
        source: 'Pattern Analysis',
      };
    }

    return {
      isSpam: false,
      spamScore: 0,
      reports: 0,
      categories: [],
      source: 'Spam Databases',
    };
  } catch (error) {
    console.error('Phone spam check error:', error);
    return null;
  }
}

async function checkSpamPatterns(phone: string): Promise<PhoneSpamResult> {
  // Known spam number prefixes (US-focused, can expand)
  const spamPrefixes = [
    // Common robocall prefixes
    '8005551212',
    '8007776666',
    // Add more known spam prefixes
  ];

  // Check for sequential or repetitive patterns (common in spoofed numbers)
  const hasRepetitivePattern = /(.)\1{5,}/.test(phone); // 6+ repeated digits
  const hasSequentialPattern = /012345|123456|234567|345678|456789|567890|098765|987654/.test(phone);
  
  // Check for known scam area codes
  const scamAreaCodes = [
    '268', // Antigua - One-ring scam
    '284', // British Virgin Islands
    '473', // Grenada
    '664', // Montserrat
    '649', // Turks and Caicos
    '767', // Dominica
    '809', '829', '849', // Dominican Republic
    '876', // Jamaica
    '900', '976', // Premium rate
  ];

  const areaCode = phone.length >= 10 ? phone.substring(0, 3) : '';
  const isScamAreaCode = scamAreaCodes.includes(areaCode);

  let spamScore = 0;
  const categories: string[] = [];

  if (hasRepetitivePattern) {
    spamScore += 30;
    categories.push('Repetitive digit pattern (likely spoofed)');
  }

  if (hasSequentialPattern) {
    spamScore += 20;
    categories.push('Sequential digit pattern');
  }

  if (isScamAreaCode) {
    spamScore += 50;
    categories.push(`High-risk area code (${areaCode}) - common in phone scams`);
  }

  if (spamPrefixes.some(prefix => phone.startsWith(prefix))) {
    spamScore += 60;
    categories.push('Known spam number prefix');
  }

  return {
    isSpam: spamScore >= 50,
    spamScore,
    reports: 0,
    categories,
    source: 'Pattern Analysis',
  };
}

function checkPremiumRateNumber(phone: string): { isPremium: boolean; type: string } {
  // US Premium rate numbers
  if (phone.startsWith('1900') || phone.startsWith('900')) {
    return { isPremium: true, type: '900 Number (Pay-per-call)' };
  }
  if (phone.startsWith('1976') || phone.startsWith('976')) {
    return { isPremium: true, type: '976 Number (Premium rate)' };
  }

  // UK Premium rate numbers
  if (phone.startsWith('44') && (
    phone.substring(2).startsWith('9') ||
    phone.substring(2).startsWith('118')
  )) {
    return { isPremium: true, type: 'UK Premium Rate' };
  }

  // International premium patterns
  if (phone.startsWith('1809') || phone.startsWith('1876')) {
    return { isPremium: true, type: 'Caribbean Premium (potential callback scam)' };
  }

  return { isPremium: false, type: '' };
}

// ============================================
// EMAIL PATTERN ANALYSIS
// ============================================

export interface EmailPatternResult {
  suspicious: boolean;
  score: number;
  flags: string[];
}

export function analyzeEmailPatterns(email: string): EmailPatternResult {
  const [localPart, domain] = email.toLowerCase().split('@');
  const flags: string[] = [];
  let score = 0;

  // Check for random string patterns (common in fake emails)
  const hasRandomString = /^[a-z0-9]{15,}$/.test(localPart); // Long random alphanumeric
  const hasMostlyNumbers = (localPart.replace(/[^0-9]/g, '').length / localPart.length) > 0.6;
  const hasExcessiveDots = (localPart.match(/\./g) || []).length > 3;
  const hasExcessiveNumbers = /\d{6,}/.test(localPart); // 6+ consecutive digits
  
  // Check for suspicious patterns
  const suspiciousPatterns = [
    { pattern: /^(admin|support|help|service|info|contact|sales|billing)\d+@/, flag: 'Impersonating official account with numbers' },
    { pattern: /^[a-z]{1,2}\d{8,}@/, flag: 'Short letters + long number (auto-generated)' },
    { pattern: /(security|verify|confirm|update|suspend|limit|alert|urgent)/, flag: 'Contains phishing keywords' },
    { pattern: /^no-?reply.*\d+@/, flag: 'No-reply with numbers (suspicious)' },
    { pattern: /[0-9]{4}-[0-9]{4}/, flag: 'Contains number sequences' },
  ];

  if (hasRandomString) {
    score += 25;
    flags.push('Local part appears to be random string');
  }

  if (hasMostlyNumbers) {
    score += 20;
    flags.push('Local part is mostly numbers');
  }

  if (hasExcessiveDots) {
    score += 15;
    flags.push('Excessive dots in local part');
  }

  if (hasExcessiveNumbers) {
    score += 15;
    flags.push('Contains long number sequence');
  }

  for (const { pattern, flag } of suspiciousPatterns) {
    if (pattern.test(email)) {
      score += 20;
      flags.push(flag);
    }
  }

  // Check for look-alike domain patterns
  const lookAlikePatterns = [
    { pattern: /paypa[l1]|paypal[0-9]/, flag: 'PayPal look-alike' },
    { pattern: /amaz[o0]n|amazon[0-9]/, flag: 'Amazon look-alike' },
    { pattern: /g[o0]{2}gle|google[0-9]/, flag: 'Google look-alike' },
    { pattern: /faceb[o0]{2}k|facebook[0-9]/, flag: 'Facebook look-alike' },
    { pattern: /micr[o0]s[o0]ft|microsoft[0-9]/, flag: 'Microsoft look-alike' },
    { pattern: /app[l1]e|apple[0-9]/, flag: 'Apple look-alike' },
    { pattern: /netf[l1]ix|netflix[0-9]/, flag: 'Netflix look-alike' },
  ];

  for (const { pattern, flag } of lookAlikePatterns) {
    if (pattern.test(domain)) {
      score += 40;
      flags.push(flag);
    }
  }

  // Check domain for suspicious TLDs with brand names
  const suspiciousDomainPatterns = [
    { pattern: /-secure|-login|-verify|-confirm|-update/, flag: 'Domain contains security/action keywords' },
    { pattern: /\.(tk|ml|ga|cf|gq)$/, flag: 'Free/suspicious TLD' },
  ];

  for (const { pattern, flag } of suspiciousDomainPatterns) {
    if (pattern.test(domain)) {
      score += 25;
      flags.push(flag);
    }
  }

  return {
    suspicious: score >= 40,
    score,
    flags,
  };
}

// ============================================
// NOMOROBO / SPAM CALLER DATABASE (Web scrape alternative)
// ============================================

export async function checkSpamCallerDB(phone: string): Promise<{
  found: boolean;
  spamScore: number;
  reportCount: number;
  type: string | null;
} | null> {
  // This checks against publicly available spam databases
  // In production, you'd want to use proper APIs or respect rate limits
  
  try {
    const _cleanPhone = phone.replace(/[^0-9]/g, '');
    
    // Try to check against FTC complaint database patterns
    // (In reality, you'd query actual APIs here)
    
    // For now, return basic analysis
    return {
      found: false,
      spamScore: 0,
      reportCount: 0,
      type: null,
    };
  } catch (error) {
    console.error('Spam caller DB check error:', error);
    return null;
  }
}

// ============================================
// COMPREHENSIVE EMAIL RISK ASSESSMENT
// ============================================

export async function assessEmailRisk(email: string): Promise<{
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  flags: string[];
  sources: string[];
}> {
  const flags: string[] = [];
  const sources: string[] = [];
  let riskScore = 0;

  // Run all checks in parallel
  const [
    ipqsResult,
    hibpResult,
    patternResult,
  ] = await Promise.all([
    checkIPQSEmail(email, process.env.IPQUALITYSCORE_API_KEY ?? ''),
    checkHaveIBeenPwned(email, process.env.HIBP_API_KEY ?? ''),
    Promise.resolve(analyzeEmailPatterns(email)),
  ]);

  // Evaluate IPQS results
  if (ipqsResult) {
    sources.push('IPQualityScore');
    
    if (ipqsResult.honeypot) {
      riskScore += 80;
      flags.push('HONEYPOT DETECTED - Known spam trap');
    }
    if (ipqsResult.spamTrap) {
      riskScore += 70;
      flags.push('Spam trap email address');
    }
    if (ipqsResult.disposable) {
      riskScore += 40;
      flags.push('Disposable/temporary email');
    }
    if (ipqsResult.recentAbuse) {
      riskScore += 50;
      flags.push('Recent abuse detected');
    }
    if (ipqsResult.leaked) {
      riskScore += 30;
      flags.push('Email found in data leaks');
    }
    if (ipqsResult.fraudScore >= 75) {
      riskScore += 40;
      flags.push(`High fraud score: ${ipqsResult.fraudScore}`);
    } else if (ipqsResult.fraudScore >= 50) {
      riskScore += 20;
      flags.push(`Moderate fraud score: ${ipqsResult.fraudScore}`);
    }
    if (!ipqsResult.valid) {
      riskScore += 30;
      flags.push('Invalid email address');
    }
  }

  // Evaluate HIBP results
  if (hibpResult) {
    sources.push('Have I Been Pwned');
    
    if (hibpResult.breached) {
      const breachScore = Math.min(40, hibpResult.breachCount * 5);
      riskScore += breachScore;
      flags.push(`Found in ${hibpResult.breachCount} data breach(es)`);
      
      // Check for sensitive breaches
      const sensitiveBreaches = hibpResult.breaches.filter(b => b.isSensitive);
      if (sensitiveBreaches.length > 0) {
        riskScore += 20;
        flags.push(`Found in ${sensitiveBreaches.length} sensitive breach(es)`);
      }
    }
    
    if (hibpResult.pasteCount > 0) {
      riskScore += 15;
      flags.push(`Found in ${hibpResult.pasteCount} paste(s)`);
    }
  }

  // Evaluate pattern analysis
  if (patternResult.suspicious) {
    sources.push('Pattern Analysis');
    riskScore += patternResult.score;
    flags.push(...patternResult.flags);
  }

  // Cap risk score at 100
  riskScore = Math.min(100, riskScore);

  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 80) {
    riskLevel = 'critical';
  } else if (riskScore >= 50) {
    riskLevel = 'high';
  } else if (riskScore >= 25) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  return {
    riskLevel,
    riskScore,
    flags,
    sources,
  };
}

// ============================================
// COMPREHENSIVE PHONE RISK ASSESSMENT
// ============================================

export async function assessPhoneRisk(phone: string): Promise<{
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  flags: string[];
  sources: string[];
}> {
  const flags: string[] = [];
  const sources: string[] = [];
  let riskScore = 0;

  // Run all checks in parallel
  const [
    ipqsResult,
    spamDbResult,
  ] = await Promise.all([
    checkIPQSPhone(phone, process.env.IPQUALITYSCORE_API_KEY ?? ''),
    checkPhoneSpamDatabases(phone),
  ]);

  // Evaluate IPQS results
  if (ipqsResult) {
    sources.push('IPQualityScore');
    
    if (ipqsResult.spammer) {
      riskScore += 80;
      flags.push('KNOWN SPAMMER');
    }
    if (ipqsResult.recentAbuse) {
      riskScore += 50;
      flags.push('Recent abuse detected');
    }
    if (ipqsResult.voip) {
      riskScore += 25;
      flags.push('VoIP number (commonly used by scammers)');
    }
    if (ipqsResult.prepaid) {
      riskScore += 15;
      flags.push('Prepaid phone (harder to trace)');
    }
    if (ipqsResult.risky) {
      riskScore += 35;
      flags.push('Flagged as risky');
    }
    if (ipqsResult.leaked) {
      riskScore += 20;
      flags.push('Phone found in data leaks');
    }
    if (ipqsResult.fraudScore >= 75) {
      riskScore += 40;
      flags.push(`High fraud score: ${ipqsResult.fraudScore}`);
    } else if (ipqsResult.fraudScore >= 50) {
      riskScore += 20;
      flags.push(`Moderate fraud score: ${ipqsResult.fraudScore}`);
    }
    if (!ipqsResult.valid) {
      riskScore += 30;
      flags.push('Invalid phone number');
    }
    if (!ipqsResult.active) {
      riskScore += 20;
      flags.push('Phone number not active');
    }
  }

  // Evaluate spam database results
  if (spamDbResult) {
    sources.push(spamDbResult.source);
    
    if (spamDbResult.isSpam) {
      riskScore += 60;
      flags.push('Found in spam databases');
    }
    
    if (spamDbResult.categories.length > 0) {
      flags.push(...spamDbResult.categories);
      riskScore += spamDbResult.spamScore;
    }
  }

  // Cap risk score at 100
  riskScore = Math.min(100, riskScore);

  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 80) {
    riskLevel = 'critical';
  } else if (riskScore >= 50) {
    riskLevel = 'high';
  } else if (riskScore >= 25) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  return {
    riskLevel,
    riskScore,
    flags,
    sources,
  };
}
