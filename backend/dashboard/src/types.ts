export interface HealthResponse {
  app_name: string;
  status: string;
  environment: string;
}

export interface AIStatusResponse {
  mode: string;
  ollama_available: boolean;
  ollama_reachable: boolean;
  ollama_models_found: string[];
  ollama_selected_model: string | null;
  ollama_inference_verified: boolean;
  cloud_ai_configured: boolean;
  cloud_ai_enabled: boolean;
  cloud_model: string;
  preferred_provider: string;
  last_health_check?: string;
}

export interface DecisionDetails {
  summary: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
  risk_score: number;
  action: 'ALLOW' | 'WARN' | 'BLOCK';
  confidence_level?: string;
  evidence_completeness?: number;
  supporting_factors?: string[];
  benign_factors?: string[];
  contradictory_factors?: string[];
  missing_factors?: string[];
  policy_version?: string;
}

export interface DomainImpersonationDetails {
  status: string;
  impersonation_detected: boolean;
  matched_brand?: string | null;
  official_target_domain?: string | null;
  similarity_score?: number;
  detection_techniques?: string[];
  supporting_evidence?: string[];
  confidence?: number;
  reasoning?: string;
}

export interface AIExplanationPayload {
  provider?: string;
  model?: string;
  is_cloud?: boolean;
  latency_ms?: number;
  short_explanation?: string;
  key_suspicious_indicators?: string[];
  benign_indicators?: string[];
  evidence_interpretation?: string;
  confidence?: number;
  recommended_action?: string;
  explanation?: string;
  error_reason?: string;
}

export interface AnalyzeResponse {
  scan_id: string;
  status: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
  risk_score: number;
  action: 'ALLOW' | 'WARN' | 'BLOCK';
  reason: string;
  checks: {
    ml?: { status: string; details?: any };
    google_safe_browsing?: { status: string; details?: any };
    virustotal?: { status: string; details?: any };
    rdap?: { status: string; details?: any };
    ai?: { status: string; details?: any };
    domain_shield?: { status: string; details?: any };
  };
  domain_impersonation?: DomainImpersonationDetails | null;
  ai_explanation?: AIExplanationPayload | null;
  confidence_level?: string;
  evidence_completeness?: number;
  decision_details?: DecisionDetails;
}

export interface ScanHistoryItem {
  scan_id: string;
  url: string;
  domain: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
  risk_score: number;
  status: string;
  created_at: string;
}

export interface ScanDetailResponse {
  scan_id: string;
  original_url: string;
  normalized_url: string;
  domain: string;
  status: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
  risk_score: number;
  action: 'ALLOW' | 'WARN' | 'BLOCK';
  reason: string;
  source?: string;
  checks?: Record<string, any>;
  confidence_level?: string;
  evidence_completeness?: number;
  decision_details?: DecisionDetails;
  created_at: string;
}
