from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, HttpUrl

# Strict verdict definition: Must be one of these exact values throughout the system
Verdict = Literal[
    "SAFE",
    "SUSPICIOUS",
    "CRITICAL",
    "MALICIOUS",
    "INSUFFICIENT_EVIDENCE",
    "INCONCLUSIVE"
]


class AnalyzeRequest(BaseModel):
    url: HttpUrl = Field(..., description="Target URL to be analyzed")
    source: str = Field(default="extension", description="Origin of request (extension, dashboard, search_guard)")
    allow_cloud_ai: Optional[bool] = Field(default=None, description="Explicit user consent to use Cloud AI (Claude) if local AI is unavailable")


class CheckResult(BaseModel):
    status: str = Field(default="not_run", description="Execution status: success, failed, not_run, not_implemented")
    details: dict[str, Any] = Field(default_factory=dict, description="Detailed findings and telemetry")


class AnalysisChecks(BaseModel):
    ml: CheckResult = Field(default_factory=CheckResult)
    google_safe_browsing: CheckResult = Field(default_factory=CheckResult)
    virustotal: CheckResult = Field(default_factory=CheckResult)
    rdap: CheckResult = Field(default_factory=CheckResult)
    ai: CheckResult = Field(default_factory=CheckResult, description="Local or Cloud AI intelligence analysis")
    domain_shield: CheckResult = Field(default_factory=CheckResult)


class AnalyzeResponse(BaseModel):
    scan_id: str = Field(..., description="Unique scan identifier")
    url: Optional[str] = Field(default=None, description="Original requested target URL")
    normalized_url: Optional[str] = Field(default=None, description="Normalized URL representation")
    status: str = Field(..., description="Processing status: completed, not_implemented, pending, failed")
    verdict: Optional[Verdict] = Field(default=None, description="Security verdict")
    risk_score: Optional[int] = Field(default=None, ge=0, le=100, description="Normalized risk score from 0 to 100")
    action: Optional[str] = Field(default=None, description="Recommended enforcement action: BLOCK, WARN, ALLOW, NONE")
    reason: Optional[str] = Field(default=None, description="Human-readable justification for the verdict")
    checks: AnalysisChecks = Field(default_factory=AnalysisChecks, description="Intelligence provider outputs")
    domain_impersonation: dict[str, Any] = Field(default_factory=dict, description="DomainShield findings")
    ai_explanation: Optional[dict[str, Any]] = Field(default=None, description="Structured AI threat explanation and indicators")
    confidence_level: Optional[str] = Field(default=None, description="Confidence classification: HIGH, MEDIUM, LOW")
    evidence_completeness: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Completeness of core provider evidence (0.0 to 1.0)")
    decision_details: Optional[dict[str, Any]] = Field(default=None, description="Deterministic decision explanation breakdown")
    timestamp: Optional[datetime] = Field(default=None, description="Analysis completion timestamp")


class BatchAnalyzeRequest(BaseModel):
    urls: list[HttpUrl] = Field(..., min_length=1, max_length=20, description="List of URLs to scan, maximum 20 per batch")
    source: str = Field(default="search_guard", description="Source of the batch scan request")
    allow_cloud_ai: Optional[bool] = Field(default=None, description="Explicit user consent to use Cloud AI (Claude) if local AI is unavailable")



class BatchAnalyzeResponse(BaseModel):
    status: str
    count: int
    message: Optional[str] = None
    results: list[dict[str, Any]] = Field(default_factory=list, description="List of batch scan findings")
    urls: Optional[list[str]] = None


class DecisionRequest(BaseModel):
    scan_id: str = Field(..., description="UUID of the scan the user is deciding upon")
    decision: Literal["PROCEED", "CANCEL", "proceed", "cancel"] = Field(..., description="User choice: PROCEED or CANCEL")


class DecisionResponse(BaseModel):
    status: str
    decision_id: str
    scan_id: str
    decision: str
    created_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    app_name: str
    status: str
    environment: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: Optional[int] = 100


class ScanHistoryItem(BaseModel):
    scan_id: str
    url: str
    domain: str
    verdict: Optional[Verdict] = None
    risk_score: Optional[int] = None
    action: Optional[str] = None
    status: str
    timestamp: Optional[datetime] = None
    created_at: Optional[datetime] = None


class ScanDetailResponse(BaseModel):
    scan_id: str
    original_url: str
    normalized_url: str
    domain: str
    status: str
    verdict: Optional[Verdict] = None
    risk_score: Optional[int] = None
    action: Optional[str] = None
    reason: Optional[str] = None
    source: str
    checks: Optional[dict[str, Any]] = None
    confidence_level: Optional[str] = None
    evidence_completeness: Optional[float] = None
    decision_details: Optional[dict[str, Any]] = None
    created_at: Optional[datetime] = None