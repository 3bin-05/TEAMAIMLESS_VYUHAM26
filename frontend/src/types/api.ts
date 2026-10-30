export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'MALICIOUS' | 'INSUFFICIENT_EVIDENCE' | 'INCONCLUSIVE';
export type PolicyAction = 'ALLOW' | 'WARN' | 'BLOCK' | 'NONE';
export type ScanStatus = 'pending' | 'completed' | 'partial' | 'failed' | 'not_implemented';
export type ProviderStatus = 'pending' | 'completed' | 'no_match' | 'unavailable' | 'timeout' | 'error' | 'success' | 'failed' | 'not_run';

export interface MLCheckDetails {
  status?: string;
  prediction?: 'legitimate' | 'phishing' | 'malicious' | string;
  confidence?: number;
  phishing_probability?: number;
  model_name?: string;
  model_version?: string;
  features_used?: number;
  [key: string]: unknown;
}

export interface MLCheck {
  status: ProviderStatus;
  prediction?: 'legitimate' | 'phishing' | 'malicious' | string;
  confidence?: number;
  phishing_probability?: number;
  model_name?: string;
  model_version?: string;
  features_used?: number;
  details?: MLCheckDetails;
}

export interface GoogleSafeBrowsingCheckDetails {
  status?: string;
  threat_detected?: boolean;
  matches?: Array<{ threat_type?: string; platform_type?: string; [key: string]: unknown }>;
  match_count?: number;
  checked_at?: string;
  [key: string]: unknown;
}

export interface GoogleSafeBrowsingCheck {
  status: ProviderStatus;
  threat_detected?: boolean;
  threat_type?: string;
  platform_type?: string;
  matches?: Array<{ threat_type?: string; platform_type?: string; [key: string]: unknown }>;
  match_count?: number;
  details?: GoogleSafeBrowsingCheckDetails;
}

export interface VirusTotalCheckDetails {
  status?: string;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reason?: string;
  checked_at?: string;
  analysis_id?: string;
  [key: string]: unknown;
}

export interface VirusTotalCheck {
  status: ProviderStatus;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reason?: string;
  analysis_id?: string;
  details?: VirusTotalCheckDetails;
}

export interface RDAPCheckDetails {
  status?: string;
  domain?: string;
  registered?: boolean;
  registrar?: string | null;
  registrant?: string | null;
  creation_date?: string | null;
  registration_date?: string | null;
  expiration_date?: string | null;
  last_updated?: string | null;
  domain_age_days?: number | null;
  nameservers?: string[];
  domain_status?: string[];
  status_codes?: string[];
  reason?: string;
  [key: string]: unknown;
}

export interface RDAPCheck {
  status: ProviderStatus;
  domain?: string;
  registered?: boolean;
  registrar?: string | null;
  registrant?: string | null;
  creation_date?: string | null;
  registration_date?: string | null;
  expiration_date?: string | null;
  last_updated?: string | null;
  domain_age_days?: number | null;
  nameservers?: string[];
  domain_status?: string[];
  status_codes?: string[];
  reason?: string;
  details?: RDAPCheckDetails;
}

export interface DomainShieldDetails {
  status?: string;
  impersonation_detected?: boolean;
  matched_brand?: string | null;
  official_target_domain?: string | null;
  official_domain?: string | null;
  observed_hostname?: string;
  registrable_domain?: string;
  similarity_score?: number | null;
  detection_techniques?: string[];
  techniques_triggered?: string[];
  supporting_evidence?: string[];
  evidence?: string[];
  confidence?: number;
  reasoning?: string;
  reason?: string;
  limitations?: string | null;
  [key: string]: unknown;
}

export interface DomainShieldCheck {
  status?: ProviderStatus;
  possible_match?: string | null;
  matched_brand?: string | null;
  official_target_domain?: string | null;
  official_domain?: string | null;
  similarity?: number | null;
  similarity_score?: number | null;
  is_lookalike?: boolean;
  impersonation_detected?: boolean;
  detection_techniques?: string[];
  supporting_evidence?: string[];
  details?: DomainShieldDetails;
}

export interface AICheckDetails {
  status?: string;
  provider?: string;
  model?: string;
  is_cloud?: boolean;
  latency_ms?: number | null;
  explanation?: string | null;
  analysis?: string | null;
  error_reason?: string | null;
  summary?: string;
  risk_assessment?: string;
  key_findings?: string[];
  supporting_signals?: string[];
  final_verdict?: string;
  final_score?: number;
  [key: string]: unknown;
}

export interface AICheck {
  status: ProviderStatus;
  provider?: string;
  model?: string;
  is_cloud?: boolean;
  latency_ms?: number | null;
  explanation?: string | null;
  error_reason?: string | null;
  details?: AICheckDetails;
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

export interface DecisionDetails {
  summary?: string;
  verdict?: Verdict;
  risk_score?: number | null;
  action?: PolicyAction;
  confidence_level?: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  evidence_completeness?: number | null;
  supporting_factors?: string[];
  benign_factors?: string[];
  contradictory_factors?: string[];
  missing_factors?: string[];
  policy_version?: string;
}

export interface AnalyzeChecks {
  ml?: MLCheck;
  google_safe_browsing?: GoogleSafeBrowsingCheck;
  virustotal?: VirusTotalCheck;
  rdap?: RDAPCheck;
  domain_shield?: DomainShieldCheck;
  ai?: AICheck;
  decision?: DecisionDetails;
  [key: string]: unknown;
}

export interface AnalyzeRequest {
  url: string;
  source?: 'dashboard' | 'chrome_extension' | 'search_guard' | string;
  allow_cloud_ai?: boolean | null;
}

export interface AnalyzeResponse {
  scan_id: string;
  url: string;
  original_url?: string;
  normalized_url?: string;
  domain?: string;
  status: ScanStatus;
  verdict: Verdict;
  risk_score?: number | null;
  action: PolicyAction;
  reason?: string;
  reasons?: string[];
  confidence_level?: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  evidence_completeness?: number | null;
  decision_details?: DecisionDetails;
  checks?: AnalyzeChecks;
  domain_impersonation?: DomainShieldCheck;
  ai_explanation?: AIExplanation | null;
  timestamp?: string;
  created_at?: string;
  source?: string;
}

export interface BatchAnalyzeItemResult {
  scan_id?: string;
  status: ScanStatus;
  verdict: Verdict;
  action: PolicyAction;
  risk_score?: number | null;
  reason?: string;
  url?: string;
}

export interface BatchAnalyzeRequest {
  urls: string[];
  source?: 'search_guard' | string;
  allow_cloud_ai?: boolean | null;
}

export interface BatchAnalyzeResponse {
  status?: string;
  count?: number;
  message?: string | null;
  results?: BatchAnalyzeItemResult[] | Record<string, BatchAnalyzeItemResult>;
  urls?: string[] | null;
}

export interface ScanHistoryItem {
  scan_id: string;
  url: string;
  original_url?: string;
  domain?: string;
  verdict: Verdict;
  action: PolicyAction;
  risk_score?: number | null;
  status?: string;
  timestamp: string;
  created_at?: string;
  source?: string;
}

export interface ScanHistoryResponse {
  scans?: ScanHistoryItem[];
  total?: number;
}

export interface UserDecisionRequest {
  scan_id: string;
  decision: 'PROCEED' | 'CANCEL' | 'proceed' | 'cancel';
}

export interface UserDecisionResponse {
  status: string;
  decision_id?: string;
  scan_id?: string;
  decision?: string;
  created_at?: string;
}

export interface HealthResponse {
  app_name?: string;
  status: string;
  environment?: string;
  version?: string;
  timestamp?: string;
  database?: string;
  cache?: string;
}
