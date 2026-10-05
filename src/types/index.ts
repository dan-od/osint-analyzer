export type AnalysisType = 'email' | 'domain' | 'phone' | 'crypto' | 'ip';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface AnalysisResult {
  type: AnalysisType;
  query: string;
  timestamp: string;
  riskScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  summary: string;
  indicators: Indicator[];
  details: Record<string, AnalysisDetail>;
  recommendations: string[];
  /** Sources that were not queried (no API key, quota used up, rate limited) */
  skippedSources?: SkippedSource[];
  /** Blocklist / threat-feed aggregation (IPs and domains) */
  blocklist?: BlocklistCoverage;
  /** Links to open the target on third-party sites */
  pivots?: PivotLink[];
  /** Flat values for tables and CSV export */
  facts?: ResultFacts;
  /** Sources that gave a usable answer, out of those planned for this target */
  sources?: { answered: number; total: number };
  elapsedMs?: number;
}

/** One row of the findings table while a check is running */
export interface PlannedTask {
  id: string;
  label: string;
  source: string;
  /** How many sources this check covers (blocklists cover dozens) */
  sources: number;
}

/** Streamed by /api/analyze/stream as newline-delimited JSON */
export type AnalysisEvent =
  | { type: 'plan'; target: string; kind: AnalysisType; tasks: PlannedTask[]; totalSources: number; pivots: PivotLink[] }
  | { type: 'progress'; done: number; answered: number }
  | { type: 'task'; id: string; state: 'done' | 'skipped'; indicators: Indicator[]; done: number; answered: number }
  | { type: 'result'; result: AnalysisResult }
  | { type: 'error'; error: string; status?: number };

export interface ResultFacts {
  verdict: string;
  abuseScore: number | null;
  vtDetections: string | null;
  blocklistHits: string | null;
  proxyType: string | null;
  country: string | null;
  /** The most serious finding, in a few words */
  topFinding: string | null;
}

export interface PivotLink {
  label: string;
  /** What the link opens (the domain for an email, the hosting IP on AbuseIPDB) */
  target: string;
  url: string;
}

/** How much a listing on this source should count */
export type BlocklistTrust = 'high' | 'medium' | 'low' | 'noisy';

export interface BlocklistSourceResult {
  id: string;
  name: string;
  kind: 'dnsbl' | 'feed' | 'api';
  trust: BlocklistTrust;
  /** refused = the list declined to answer (e.g. public resolver), never counted as listed */
  status: 'listed' | 'clean' | 'refused' | 'error' | 'skipped';
  detail?: string;
}

export interface BlocklistCoverage {
  /** Sources that listed the target */
  flagged: number;
  /** Sources that gave a usable answer (listed or clean) */
  checked: number;
  /** All sources attempted, including refused/errored/skipped */
  total: number;
  /** 0–100, listings weighted by source trust */
  weightedScore: number;
  sources: BlocklistSourceResult[];
}

export interface SkippedSource {
  service: string;
  name: string;
  reason: string;
}

export interface Indicator {
  id: string;
  name: string;
  status: 'pass' | 'warning' | 'fail' | 'unknown';
  description: string;
  severity: RiskLevel;
  source: string;
}

export interface AnalysisDetail {
  title: string;
  data: Record<string, string | number | boolean | null>;
  status: 'pass' | 'warning' | 'fail' | 'unknown';
}

// Email specific types
export interface EmailAnalysis extends AnalysisResult {
  type: 'email';
  details: {
    domain: AnalysisDetail;
    provider: AnalysisDetail;
    syntax: AnalysisDetail;
    reputation: AnalysisDetail;
    breaches: AnalysisDetail;
  };
}

// Domain specific types
export interface DomainAnalysis extends AnalysisResult {
  type: 'domain';
  details: {
    whois: AnalysisDetail;
    dns: AnalysisDetail;
    ssl: AnalysisDetail;
    reputation: AnalysisDetail;
    abuseipdb: AnalysisDetail;
  };
}

// Phone specific types
export interface PhoneAnalysis extends AnalysisResult {
  type: 'phone';
  details: {
    carrier: AnalysisDetail;
    location: AnalysisDetail;
    lineType: AnalysisDetail;
    spamReports: AnalysisDetail;
  };
}

// Crypto specific types
export interface CryptoAnalysis extends AnalysisResult {
  type: 'crypto';
  details: {
    blockchain: AnalysisDetail;
    transactions: AnalysisDetail;
    associations: AnalysisDetail;
    scamDatabase: AnalysisDetail;
  };
}

// API Response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

// Input validation
export interface ValidationResult {
  isValid: boolean;
  type: AnalysisType | null;
  normalizedInput: string;
  error?: string;
}
