export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'CRITICAL' | 'MALICIOUS' | 'INSUFFICIENT_EVIDENCE' | 'INCONCLUSIVE';
export type PolicyAction = 'ALLOW' | 'WARN' | 'BLOCK';
export type ScanStatus = 'pending' | 'completed' | 'partial' | 'failed';

export type NavigationState =
  | 'PENDING'
  | 'ANALYZING'
  | 'SAFE'
  | 'SUSPICIOUS'
  | 'MALICIOUS'
  | 'AUTHORIZED'
  | 'BLOCKED'
  | 'EXPIRED'
  | 'FAILED';

export interface VerificationRecord {
  navId: string;
  tabId: number;
  originalUrl: string;
  normalizedUrl: string;
  destinationHost: string;
  state: NavigationState;
  verdict?: Verdict;
  action?: PolicyAction;
  createdAt: number;
  authorizedAt?: number;
  expiresAt: number;
  consumed: boolean;
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
  checks?: Record<string, unknown>;
  domain_impersonation?: {
    possible_match?: string | null;
    official_domain?: string | null;
    similarity?: number | null;
    is_lookalike?: boolean;
  };
  ai_explanation?: {
    risk_level?: string;
    summary?: string;
    reasons?: Array<{
      title: string;
      explanation: string;
      source: string;
      severity?: string;
    }>;
    anomalies?: Array<{
      title: string;
      explanation: string;
      source?: string;
    }>;
    domain_history?: {
      status?: string;
      explanation?: string;
    };
    organization_verification?: {
      status?: string;
      explanation?: string;
    };
    similar_sites?: string[];
    recommendation?: string;
    [key: string]: unknown;
  };
  timestamp?: string;
}

export interface BatchItemResult {
  scan_id?: string;
  status: ScanStatus;
  verdict: Verdict;
  action: PolicyAction;
  risk_score?: number | null;
  reason?: string;
}

export interface BatchAnalyzeResponse {
  results: Record<string, BatchItemResult>;
}

export interface NavigationApprovalToken {
  attemptId: string;
  tabId: number;
  url: string;
  normalizedUrl: string;
  timestamp: number;
  expiresAt: number;
}

export type ExtensionMessageType =
  | 'ANALYZE_URL'
  | 'BATCH_ANALYZE'
  | 'CHECK_APPROVAL'
  | 'CONSUME_APPROVAL'
  | 'REGISTER_APPROVAL'
  | 'AUTHORIZE_NAVIGATION'
  | 'GET_NAVIGATION_STATE'
  | 'SET_NAVIGATION_STATE'
  | 'CANCEL_NAVIGATION'
  | 'RECORD_DECISION'
  | 'GET_CONFIG'
  | 'SET_CONFIG'
  | 'HEALTH_CHECK';

export interface ExtensionMessage<T = unknown> {
  type: ExtensionMessageType;
  payload: T;
}

export interface AnalyzeUrlPayload {
  url: string;
  attemptId?: string;
  navId?: string;
  tabId?: number;
  source?: 'chrome_extension' | 'search_guard' | 'dashboard';
}

export interface CheckApprovalPayload {
  tabId: number;
  url: string;
  attemptId?: string;
  navId?: string;
}

export interface AuthorizeNavigationPayload {
  navId: string;
  tabId?: number;
  url: string;
  verdict: Verdict | 'SUSPICIOUS_PROCEED';
}

export interface RecordDecisionPayload {
  scan_id?: string;
  url: string;
  decision: 'proceed' | 'cancel';
}
