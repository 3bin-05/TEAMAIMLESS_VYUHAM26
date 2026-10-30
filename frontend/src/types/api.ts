export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'MALICIOUS' | 'INSUFFICIENT_EVIDENCE' | 'INCONCLUSIVE';
export type PolicyAction = 'ALLOW' | 'WARN' | 'BLOCK';
export type ScanStatus = 'pending' | 'completed' | 'partial' | 'failed';
export type ProviderStatus = 'pending' | 'completed' | 'no_match' | 'unavailable' | 'timeout' | 'error';

export interface MLCheck {
  status: ProviderStatus;
  prediction?: 'legitimate' | 'phishing' | 'malicious' | string;
  confidence?: number;
  model_version?: string;
  details?: Record<string, unknown>;
}

export interface GoogleSafeBrowsingCheck {
  status: ProviderStatus;
  threat_detected?: boolean;
  threat_type?: string;
  platform_type?: string;
}

export interface VirusTotalCheck {
  status: ProviderStatus;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  analysis_id?: string;
}

export interface RDAPCheck {
  status: ProviderStatus;
  domain?: string;
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  domain_age_days?: number;
  nameservers?: string[];
  status_codes?: string[];
}

export interface DomainShieldCheck {
  possible_match?: string | null;
  official_domain?: string | null;
  similarity?: number | null;
  is_lookalike?: boolean;
}

export interface AIReasonItem {
  title: string;
  explanation: string;
  source: string;
  severity?: 'low' | 'medium' | 'high' | 'critical' | string;
}

export interface AIAnomalyItem {
  title: string;
  explanation: string;
  source?: string;
}

export interface AIDomainHistory {
  status?: string;
  explanation?: string;
}

export interface AIOrganizationVerification {
  status?: string;
  explanation?: string;
}

export interface AIExplanation {
  risk_level?: 'safe' | 'suspicious' | 'malicious' | 'inconclusive' | string;
  summary?: string;
  reasons?: AIReasonItem[];
  anomalies?: AIAnomalyItem[];
  domain_history?: AIDomainHistory;
  organization_verification?: AIOrganizationVerification;
  similar_sites?: string[];
  recommendation?: 'allow' | 'warn' | 'block' | 'inconclusive' | string;
  explanation?: string;
  suspicious_indicators?: string[];
  benign_indicators?: string[];
  confidence_score?: number;
  recommended_action?: string;
  next_steps?: string;
  provider?: string;
  model?: string;
  is_cloud?: boolean;
  latency_ms?: number;
  [key: string]: unknown;
}

export interface AnalyzeChecks {
  ml?: MLCheck;
  google_safe_browsing?: GoogleSafeBrowsingCheck;
  virustotal?: VirusTotalCheck;
  rdap?: RDAPCheck;
  [key: string]: unknown;
}

export interface AnalyzeRequest {
  url: string;
  source: 'dashboard' | 'chrome_extension' | 'search_guard';
}

export interface AnalyzeResponse {
  scan_id: string;
  url: string;
  normalized_url?: string;
  status: ScanStatus;
  verdict: Verdict;
  risk_score?: number | null;
  action: PolicyAction;
  reason?: string;
  checks?: AnalyzeChecks;
  domain_impersonation?: DomainShieldCheck;
  ai_explanation?: AIExplanation;
  timestamp?: string;
}

export interface BatchAnalyzeItemResult {
  scan_id?: string;
  status: ScanStatus;
  verdict: Verdict;
  action: PolicyAction;
  risk_score?: number | null;
  reason?: string;
}

export interface BatchAnalyzeRequest {
  urls: string[];
  source: 'search_guard';
}

export interface BatchAnalyzeResponse {
  results: Record<string, BatchAnalyzeItemResult>;
}

export interface ScanHistoryItem {
  scan_id: string;
  url: string;
  domain?: string;
  verdict: Verdict;
  action: PolicyAction;
  risk_score?: number | null;
  timestamp: string;
  source?: string;
}

export interface ScanHistoryResponse {
  scans: ScanHistoryItem[];
  total?: number;
}

export interface UserDecisionRequest {
  scan_id?: string;
  url: string;
  decision: 'proceed' | 'cancel';
  timestamp: string;
}

export interface UserDecisionResponse {
  status: string;
}

export interface HealthResponse {
  status: string;
  version?: string;
  timestamp?: string;
  database?: string;
  cache?: string;
}
