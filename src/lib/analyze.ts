import { 
  AnalysisResult, 
  AnalysisType, 
  Indicator, 
  RiskLevel,
  AnalysisDetail 
} from '@/types';
import { getRiskLevel } from './utils';
import {
  performDnsLookup,
  checkAbuseIPDB,
  checkEmailRep,
  checkPhone,
  checkVirusTotal,
  checkBitcoinWallet,
  checkEthereumWallet,
  verifyEmailHunter,
  CryptoResult,
} from './osint-apis';
import { lookupDomain } from './rdap';

// ============================================
// EMAIL ANALYSIS
// ============================================

async function analyzeEmail(email: string): Promise<AnalysisResult> {
  const domain = email.split('@')[1];
  const indicators: Indicator[] = [];
  const details: Record<string, AnalysisDetail> = {};
  
  // 1. DNS Lookup (always works - no API key needed)
  const dnsResult = await performDnsLookup(domain);
  
  indicators.push({
    id: 'mx-records',
    name: 'MX Records',
    status: dnsResult.hasMx ? 'pass' : 'fail',
    description: dnsResult.hasMx 
      ? `Valid MX records found: ${dnsResult.mx.map(m => m.exchange).join(', ')}`
      : 'No MX records found - domain cannot receive email',
    severity: dnsResult.hasMx ? 'low' : 'critical',
    source: 'DNS Lookup'
  });

  indicators.push({
    id: 'spf-record',
    name: 'SPF Record',
    status: dnsResult.hasSpf ? 'pass' : 'warning',
    description: dnsResult.hasSpf 
      ? 'SPF record configured for email authentication'
      : 'No SPF record found - emails may be spoofable',
    severity: dnsResult.hasSpf ? 'low' : 'medium',
    source: 'DNS Lookup'
  });

  indicators.push({
    id: 'dmarc-record',
    name: 'DMARC Record',
    status: dnsResult.hasDmarc ? 'pass' : 'warning',
    description: dnsResult.hasDmarc 
      ? 'DMARC policy configured for email protection'
      : 'No DMARC record found - limited email authentication',
    severity: dnsResult.hasDmarc ? 'low' : 'medium',
    source: 'DNS Lookup'
  });

  details.dns = {
    title: 'DNS Configuration',
    data: {
      mxRecords: dnsResult.mx.map(m => m.exchange).join(', ') || 'None',
      spfRecord: dnsResult.spf || 'Not configured',
      dmarcRecord: dnsResult.dmarc ? 'Configured' : 'Not configured',
      nameservers: dnsResult.ns.join(', ') || 'None',
    },
    status: dnsResult.hasMx && dnsResult.hasSpf ? 'pass' : 'warning'
  };

  // 2. EmailRep.io (works without key, better with key)
  const emailRepResult = await checkEmailRep(email);
  
  if (emailRepResult) {
    indicators.push({
      id: 'email-reputation',
      name: 'Email Reputation',
      status: emailRepResult.reputation === 'high' ? 'pass' 
            : emailRepResult.reputation === 'medium' ? 'warning'
            : emailRepResult.reputation === 'low' ? 'fail'
            : 'unknown',
      description: `Reputation: ${emailRepResult.reputation} (${emailRepResult.references} references found)`,
      severity: emailRepResult.reputation === 'high' ? 'low' 
              : emailRepResult.reputation === 'medium' ? 'medium'
              : 'high',
      source: 'EmailRep.io'
    });

    indicators.push({
      id: 'suspicious-check',
      name: 'Suspicious Activity',
      status: emailRepResult.suspicious ? 'fail' : 'pass',
      description: emailRepResult.suspicious 
        ? 'Email flagged as suspicious by threat intelligence'
        : 'No suspicious activity detected',
      severity: emailRepResult.suspicious ? 'high' : 'low',
      source: 'EmailRep.io'
    });

    if (emailRepResult.details.dataBreach) {
      indicators.push({
        id: 'data-breach',
        name: 'Data Breach',
        status: 'warning',
        description: 'Email found in known data breaches',
        severity: 'medium',
        source: 'EmailRep.io'
      });
    }

    if (emailRepResult.details.disposable) {
      indicators.push({
        id: 'disposable-email',
        name: 'Disposable Email',
        status: 'fail',
        description: 'This is a disposable/temporary email address',
        severity: 'high',
        source: 'EmailRep.io'
      });
    }

    details.emailRep = {
      title: 'Email Reputation',
      data: {
        reputation: emailRepResult.reputation,
        suspicious: emailRepResult.suspicious,
        references: emailRepResult.references,
        blacklisted: emailRepResult.details.blacklisted,
        dataBreach: emailRepResult.details.dataBreach,
        credentialsLeaked: emailRepResult.details.credentialsLeaked,
        freeProvider: emailRepResult.details.freeProvider,
        disposable: emailRepResult.details.disposable,
        deliverable: emailRepResult.details.deliverable,
        profiles: emailRepResult.details.profiles.join(', ') || 'None found',
      },
      status: emailRepResult.suspicious ? 'fail' : emailRepResult.reputation === 'high' ? 'pass' : 'warning'
    };
  }

  // 3. Hunter.io verification (if API key available)
  const hunterResult = await verifyEmailHunter(email, process.env.HUNTER_API_KEY ?? '');
  
  if (hunterResult) {
    indicators.push({
      id: 'email-deliverable',
      name: 'Email Deliverability',
      status: hunterResult.result === 'deliverable' ? 'pass' 
            : hunterResult.result === 'risky' ? 'warning' 
            : 'fail',
      description: `Email verification: ${hunterResult.result} (score: ${hunterResult.score}/100)`,
      severity: hunterResult.result === 'deliverable' ? 'low' : 'medium',
      source: 'Hunter.io'
    });

    details.hunterVerification = {
      title: 'Email Verification',
      data: {
        result: hunterResult.result,
        score: hunterResult.score,
        gibberish: hunterResult.gibberish,
        disposable: hunterResult.disposable,
        webmail: hunterResult.webmail,
        smtpValid: hunterResult.smtpCheck,
      },
      status: hunterResult.result === 'deliverable' ? 'pass' : 'warning'
    };
  }

  // 4. WHOIS lookup for domain age
  const whoisResult = await lookupDomain(domain);
  const isNewDomain = whoisResult?.ageDays != null && whoisResult.ageDays < 365;
  
  if (whoisResult) {
    indicators.push({
      id: 'domain-age',
      name: 'Domain Age',
      status: isNewDomain ? 'warning' : 'pass',
      description: whoisResult.ageDays 
        ? `Domain is ${whoisResult.ageDays} days old${isNewDomain ? ' (newly registered)' : ''}`
        : 'Domain age unknown',
      severity: isNewDomain ? 'high' : 'low',
      source: 'WHOIS Lookup'
    });

    details.whois = {
      title: 'Domain WHOIS',
      data: {
        registrar: whoisResult.registrar || 'Unknown',
        creationDate: whoisResult.createdAt || 'Unknown',
        expirationDate: whoisResult.expiresAt || 'Unknown',
        domainAge: whoisResult.ageDays ? `${whoisResult.ageDays} days` : 'Unknown',
        nameServers: whoisResult.nameservers.join(', ') || 'Unknown',
      },
      status: isNewDomain ? 'warning' : 'pass'
    };
  }

  return buildResult('email', email, indicators, details);
}

// ============================================
// DOMAIN ANALYSIS
// ============================================

async function analyzeDomain(domain: string): Promise<AnalysisResult> {
  const indicators: Indicator[] = [];
  const details: Record<string, AnalysisDetail> = {};

  // 1. DNS Lookup
  const dnsResult = await performDnsLookup(domain);
  
  indicators.push({
    id: 'dns-resolution',
    name: 'DNS Resolution',
    status: dnsResult.a.length > 0 ? 'pass' : 'fail',
    description: dnsResult.a.length > 0 
      ? `Domain resolves to: ${dnsResult.a.join(', ')}`
      : 'Domain does not resolve to any IP address',
    severity: dnsResult.a.length > 0 ? 'low' : 'critical',
    source: 'DNS Lookup'
  });

  indicators.push({
    id: 'mail-config',
    name: 'Mail Configuration',
    status: dnsResult.hasMx ? 'pass' : 'unknown',
    description: dnsResult.hasMx 
      ? `Mail servers: ${dnsResult.mx.map(m => m.exchange).slice(0, 3).join(', ')}`
      : 'No mail servers configured',
    severity: 'low',
    source: 'DNS Lookup'
  });

  details.dns = {
    title: 'DNS Records',
    data: {
      aRecords: dnsResult.a.join(', ') || 'None',
      mxRecords: dnsResult.mx.map(m => m.exchange).join(', ') || 'None',
      nsRecords: dnsResult.ns.join(', ') || 'None',
      spfRecord: dnsResult.hasSpf ? 'Present' : 'Missing',
      dmarcRecord: dnsResult.hasDmarc ? 'Present' : 'Missing',
    },
    status: dnsResult.a.length > 0 ? 'pass' : 'fail'
  };

  // 2. WHOIS Lookup
  const whoisResult = await lookupDomain(domain);
  const isNewDomain = whoisResult?.ageDays != null && whoisResult.ageDays < 365;
  
  if (whoisResult) {
    indicators.push({
      id: 'domain-age',
      name: 'Domain Age',
      status: isNewDomain ? 'warning' : 'pass',
      description: whoisResult.ageDays 
        ? `Registered ${whoisResult.ageDays} days ago${isNewDomain ? ' - NEWLY REGISTERED' : ''}`
        : 'Domain age unknown',
      severity: isNewDomain ? 'high' : 'low',
      source: 'WHOIS Lookup'
    });

    details.whois = {
      title: 'WHOIS Information',
      data: {
        registrar: whoisResult.registrar || 'Unknown',
        creationDate: whoisResult.createdAt || 'Unknown',
        expirationDate: whoisResult.expiresAt || 'Unknown',
        updatedDate: whoisResult.updatedAt || 'Unknown',
        domainAge: whoisResult.ageDays ? `${whoisResult.ageDays} days` : 'Unknown',
        status: whoisResult.status.join(', ') || 'Unknown',
      },
      status: isNewDomain ? 'warning' : 'pass'
    };
  }

  // 3. AbuseIPDB check (if domain resolves to IP)
  if (dnsResult.a.length > 0) {
    const abuseResult = await checkAbuseIPDB(dnsResult.a[0], process.env.ABUSEIPDB_API_KEY ?? '');
    
    if (abuseResult) {
      indicators.push({
        id: 'abuse-reports',
        name: 'Abuse Reports',
        status: abuseResult.abuseConfidenceScore > 50 ? 'fail' 
              : abuseResult.abuseConfidenceScore > 10 ? 'warning' 
              : 'pass',
        description: `Abuse confidence score: ${abuseResult.abuseConfidenceScore}% (${abuseResult.totalReports} reports)`,
        severity: abuseResult.abuseConfidenceScore > 50 ? 'critical' 
                : abuseResult.abuseConfidenceScore > 10 ? 'high' 
                : 'low',
        source: 'AbuseIPDB'
      });

      details.abuseipdb = {
        title: 'AbuseIPDB Report',
        data: {
          ipAddress: abuseResult.ipAddress,
          confidenceScore: `${abuseResult.abuseConfidenceScore}%`,
          totalReports: abuseResult.totalReports,
          countryCode: abuseResult.countryCode || 'Unknown',
          isp: abuseResult.isp || 'Unknown',
          usageType: abuseResult.usageType || 'Unknown',
          lastReported: abuseResult.lastReportedAt || 'Never',
        },
        status: abuseResult.abuseConfidenceScore > 10 ? 'warning' : 'pass'
      };
    }
  }

  // 4. VirusTotal check
  const vtResult = await checkVirusTotal(domain, 'domain', process.env.VIRUSTOTAL_API_KEY ?? '');
  
  if (vtResult) {
    indicators.push({
      id: 'virustotal',
      name: 'VirusTotal Scan',
      status: vtResult.positives > 5 ? 'fail' 
            : vtResult.positives > 0 ? 'warning' 
            : 'pass',
      description: `${vtResult.positives}/${vtResult.total} security vendors flagged this domain`,
      severity: vtResult.positives > 5 ? 'critical' 
              : vtResult.positives > 0 ? 'high' 
              : 'low',
      source: 'VirusTotal'
    });

    details.virustotal = {
      title: 'VirusTotal Analysis',
      data: {
        detections: `${vtResult.positives}/${vtResult.total}`,
        categories: vtResult.categories.join(', ') || 'None',
        scanDate: vtResult.scanDate || 'Unknown',
        status: vtResult.isClean ? 'Clean' : 'Potentially Malicious',
      },
      status: vtResult.isClean ? 'pass' : 'fail'
    };
  }

  return buildResult('domain', domain, indicators, details);
}

// ============================================
// PHONE ANALYSIS
// ============================================

async function analyzePhone(phone: string): Promise<AnalysisResult> {
  const indicators: Indicator[] = [];
  const details: Record<string, AnalysisDetail> = {};

  // NumVerify lookup
  const phoneResult = await checkPhone(phone);
  
  if (phoneResult) {
    indicators.push({
      id: 'phone-valid',
      name: 'Phone Validation',
      status: phoneResult.valid ? 'pass' : 'fail',
      description: phoneResult.valid 
        ? 'Phone number format is valid'
        : 'Invalid phone number format',
      severity: phoneResult.valid ? 'low' : 'high',
      source: 'NumVerify'
    });

    if (phoneResult.lineType) {
      const isVoip = phoneResult.lineType.toLowerCase().includes('voip');
      indicators.push({
        id: 'line-type',
        name: 'Line Type',
        status: isVoip ? 'warning' : 'pass',
        description: `Line type: ${phoneResult.lineType}${isVoip ? ' (commonly used by scammers)' : ''}`,
        severity: isVoip ? 'high' : 'low',
        source: 'NumVerify'
      });
    }

    details.phoneInfo = {
      title: 'Phone Information',
      data: {
        valid: phoneResult.valid,
        number: phoneResult.number,
        localFormat: phoneResult.localFormat || 'N/A',
        internationalFormat: phoneResult.internationalFormat || 'N/A',
        country: phoneResult.countryName || 'Unknown',
        countryCode: phoneResult.countryCode || 'Unknown',
        location: phoneResult.location || 'Unknown',
        carrier: phoneResult.carrier || 'Unknown',
        lineType: phoneResult.lineType || 'Unknown',
      },
      status: phoneResult.valid ? 'pass' : 'fail'
    };
  } else {
    // Fallback basic validation
    const cleanPhone = phone.replace(/[^0-9+]/g, '');
    const isValidFormat = cleanPhone.length >= 10 && cleanPhone.length <= 15;
    
    indicators.push({
      id: 'phone-format',
      name: 'Format Check',
      status: isValidFormat ? 'pass' : 'warning',
      description: isValidFormat 
        ? 'Phone number appears to be valid format'
        : 'Phone number format may be invalid',
      severity: 'low',
      source: 'Basic Validation'
    });

    details.phoneInfo = {
      title: 'Phone Information',
      data: {
        number: cleanPhone,
        format: isValidFormat ? 'Valid' : 'Potentially Invalid',
        note: 'NumVerify API not configured - limited analysis',
      },
      status: isValidFormat ? 'pass' : 'warning'
    };
  }

  // Add generic warning about phone scams
  indicators.push({
    id: 'spam-warning',
    name: 'Spam Database',
    status: 'unknown',
    description: 'Unable to check community spam reports (requires additional API)',
    severity: 'low',
    source: 'System'
  });

  return buildResult('phone', phone, indicators, details);
}

// ============================================
// CRYPTO WALLET ANALYSIS
// ============================================

async function analyzeCrypto(address: string): Promise<AnalysisResult> {
  const indicators: Indicator[] = [];
  const details: Record<string, AnalysisDetail> = {};
  
  // Detect wallet type
  const isBitcoin = address.startsWith('1') || address.startsWith('3') || address.startsWith('bc1');
  const isEthereum = address.startsWith('0x') && address.length === 42;
  
  indicators.push({
    id: 'wallet-format',
    name: 'Wallet Format',
    status: (isBitcoin || isEthereum) ? 'pass' : 'fail',
    description: isBitcoin ? 'Valid Bitcoin address format' 
                : isEthereum ? 'Valid Ethereum address format'
                : 'Unknown wallet format',
    severity: (isBitcoin || isEthereum) ? 'low' : 'high',
    source: 'Format Validation'
  });

  let cryptoResult: CryptoResult | null = null;

  if (isBitcoin) {
    cryptoResult = await checkBitcoinWallet(address);
  } else if (isEthereum) {
    cryptoResult = await checkEthereumWallet(address);
  }

  if (cryptoResult) {
    indicators.push({
      id: 'wallet-activity',
      name: 'Wallet Activity',
      status: cryptoResult.txCount > 0 ? 'pass' : 'warning',
      description: `${cryptoResult.txCount} transactions found`,
      severity: 'low',
      source: isBitcoin ? 'Blockchain.info' : 'Etherscan'
    });

    // High transaction count could indicate mixer or exchange
    if (cryptoResult.txCount > 1000) {
      indicators.push({
        id: 'high-activity',
        name: 'High Transaction Volume',
        status: 'warning',
        description: 'Very high transaction count - may be exchange or mixer',
        severity: 'medium',
        source: isBitcoin ? 'Blockchain.info' : 'Etherscan'
      });
    }

    details.blockchain = {
      title: 'Blockchain Data',
      data: {
        network: cryptoResult.network,
        address: cryptoResult.address,
        balance: cryptoResult.balance,
        totalReceived: cryptoResult.totalReceived,
        totalSent: cryptoResult.totalSent,
        transactions: cryptoResult.txCount,
        firstSeen: cryptoResult.firstSeen || 'Unknown',
      },
      status: 'pass'
    };
  }

  // Scam database check placeholder
  indicators.push({
    id: 'scam-database',
    name: 'Scam Database',
    status: 'unknown',
    description: 'Scam database check not available (requires ChainAbuse API)',
    severity: 'low',
    source: 'System'
  });

  return buildResult('crypto', address, indicators, details);
}

// ============================================
// RESULT BUILDER
// ============================================

function buildResult(
  type: AnalysisType,
  query: string,
  indicators: Indicator[],
  details: Record<string, AnalysisDetail>
): AnalysisResult {
  // Calculate risk score based on indicators
  const riskScore = calculateRiskScore(indicators);
  const riskLevel = getRiskLevel(riskScore);
  
  // Calculate confidence based on how many checks succeeded
  const totalChecks = indicators.length;
  const unknownChecks = indicators.filter(i => i.status === 'unknown').length;
  const confidence = Math.round(((totalChecks - unknownChecks) / totalChecks) * 100);
  
  // Generate summary
  const failedIndicators = indicators.filter(i => i.status === 'fail');
  const warningIndicators = indicators.filter(i => i.status === 'warning');
  
  let summary: string;
  if (riskLevel === 'critical') {
    summary = `CRITICAL ALERT: ${failedIndicators.length} serious issues detected. High probability of fraudulent activity.`;
  } else if (riskLevel === 'high') {
    summary = `High risk detected: ${failedIndicators.length} failures and ${warningIndicators.length} warnings found.`;
  } else if (riskLevel === 'medium') {
    summary = `Moderate risk: ${warningIndicators.length} warning(s) detected. Exercise caution.`;
  } else {
    summary = 'Analysis complete. No significant risk indicators detected.';
  }

  // Generate recommendations
  const recommendations = generateRecommendations(type, riskLevel, indicators);

  return {
    type,
    query,
    timestamp: new Date().toISOString(),
    riskScore,
    riskLevel,
    confidence,
    summary,
    indicators,
    details,
    recommendations,
  };
}

function calculateRiskScore(indicators: Indicator[]): number {
  let score = 0;
  const weights: Record<RiskLevel, number> = {
    low: 5,
    medium: 15,
    high: 25,
    critical: 40
  };
  
  indicators.forEach(indicator => {
    if (indicator.status === 'fail') {
      score += weights[indicator.severity] * 1.5;
    } else if (indicator.status === 'warning') {
      score += weights[indicator.severity];
    }
  });
  
  return Math.min(100, Math.max(0, Math.round(score)));
}

function generateRecommendations(
  type: AnalysisType, 
  riskLevel: RiskLevel, 
  indicators: Indicator[]
): string[] {
  const recommendations: string[] = [];
  
  // Type-specific recommendations
  const typeRecs: Record<Exclude<AnalysisType, 'ip'>, string[]> = {
    email: [
      'Verify the sender through an alternative communication channel',
      'Check for spelling errors in the domain name (typosquatting)',
      'Never click links or download attachments from unverified senders',
    ],
    domain: [
      'Check for HTTPS and valid SSL certificate before entering any data',
      'Verify the domain through official company channels',
      'Look for contact information and physical address on the website',
    ],
    phone: [
      'Do not return calls to unknown numbers immediately',
      'Use a reverse phone lookup to identify the caller',
      'Register your number on the Do Not Call registry',
    ],
    crypto: [
      'Never send cryptocurrency to unknown wallet addresses',
      'Verify wallet addresses through multiple sources',
      'Use only reputable exchanges with proper verification',
    ],
  };

  // Add risk-level based prefix
  if (riskLevel === 'critical') {
    recommendations.push('⚠️ STRONGLY RECOMMEND: Avoid all interaction with this entity');
  } else if (riskLevel === 'high') {
    recommendations.push('Proceed with extreme caution - multiple risk factors detected');
  }

  // Add indicator-specific recommendations
  indicators.forEach(indicator => {
    if (indicator.status === 'fail') {
      if (indicator.id === 'disposable-email') {
        recommendations.push('This is a temporary email - do not trust for important communications');
      }
      if (indicator.id === 'domain-age' || indicator.name.includes('Domain Age')) {
        recommendations.push('Newly registered domains are frequently used in scams');
      }
      if (indicator.id === 'abuse-reports') {
        recommendations.push('This IP has been reported for abuse - avoid if possible');
      }
      if (indicator.id === 'virustotal') {
        recommendations.push('Multiple security vendors have flagged this as malicious');
      }
    }
  });

  // Add type-specific recommendations
  recommendations.push(...(type === 'ip' ? [] : typeRecs[type]).slice(0, 3 - recommendations.length > 0 ? 3 - recommendations.length : 1));

  // General recommendation
  recommendations.push('Report suspicious activity to relevant authorities (FTC, IC3, etc.)');

  return recommendations.slice(0, 5);
}

// ============================================
// MAIN EXPORT
// ============================================

export async function analyzeInput(query: string, type: AnalysisType): Promise<AnalysisResult> {
  switch (type) {
    case 'email':
      return analyzeEmail(query);
    case 'domain':
      return analyzeDomain(query);
    case 'phone':
      return analyzePhone(query);
    case 'crypto':
      return analyzeCrypto(query);
    default:
      throw new Error(`Unknown analysis type: ${type}`);
  }
}
