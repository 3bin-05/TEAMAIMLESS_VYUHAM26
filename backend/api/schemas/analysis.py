import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator


MAX_URL_LENGTH_DEFAULT = 8192


def get_max_url_length() -> int:
    try:
        return int(os.getenv("AEGIS_MAX_URL_LENGTH", str(MAX_URL_LENGTH_DEFAULT)))
    except ValueError:
        return MAX_URL_LENGTH_DEFAULT


class ClassificationEnum(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str) and value.upper() == "CRITICAL":
            return cls.MALICIOUS
        return super()._missing_(value)


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        description="The URL string to analyze for phishing threats.",
        min_length=1,
    )
    source: Optional[str] = Field(
        default="dashboard",
        description="Source of request: dashboard, chrome_extension, etc."
    )


class AnalyzeResponse(BaseModel):
    url: str = Field(..., description="Canonicalized URL analyzed")
    classification: ClassificationEnum = Field(..., description="Final risk classification (SAFE, SUSPICIOUS, CRITICAL)")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score between 0 and 100")
    reasons: List[str] = Field(default_factory=list, description="List of human-readable security risk factors")
    signals: Dict[str, Any] = Field(default_factory=dict, description="Raw feature signals from ML and cybersecurity modules")
    ai: Optional[Dict[str, Any]] = Field(default=None, description="Optional local AI advisory analysis result")
    model_version: str = Field(..., description="Active XGBoost model version")
    cached: bool = Field(..., description="Whether the result was retrieved from Trust Cache")
    analysis_time_ms: float = Field(..., description="Total analysis duration in milliseconds")
    scan_id: Optional[str] = Field(default=None, description="Unique scan identifier")
    action: Optional[str] = Field(default="ALLOW", description="Policy action (ALLOW, WARN, BLOCK)")
    status: Optional[str] = Field(default="completed", description="Scan execution status")
    verdict: Optional[str] = Field(default=None, description="Verdict matching classification")
    created_at: Optional[str] = Field(default=None, description="ISO timestamp of analysis")
    checks: Optional[Dict[str, Any]] = Field(default=None, description="Detailed subsystem checks breakdown for UI")
    domain_impersonation: Optional[Dict[str, Any]] = Field(default=None, description="DomainShield brand impersonation detection")
    ai_explanation: Optional[Dict[str, Any]] = Field(default=None, description="Human-readable structured AI explanation")
    normalized_url: Optional[str] = Field(default=None, description="Normalized target URL")
    confidence_level: Optional[str] = Field(default="HIGH", description="Confidence level (HIGH, MEDIUM, LOW)")
    reason: Optional[str] = Field(default=None, description="Primary human-readable reason summary")
    fallback_triggered: bool = Field(default=False, description="Whether fallback pipeline was activated")


class BatchAnalyzeRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        description="List of target URLs to analyze in batch for search results annotations.",
        max_length=50
    )
    source: Optional[str] = Field(
        default="search_guard",
        description="Source client identifier"
    )


class BatchAnalyzeResponse(BaseModel):
    results: List[AnalyzeResponse] = Field(default_factory=list, description="Batch analysis results")
    total: int = Field(..., description="Total URLs processed")


class UserDecisionRequest(BaseModel):
    scan_id: Optional[str] = None
    url: Optional[str] = None
    decision: str = Field(..., description="User decision, e.g. PROCEED, CANCEL")
    timestamp: Optional[str] = None


class UserDecisionResponse(BaseModel):
    status: str = "recorded"
    scan_id: Optional[str] = None
    decision: Optional[str] = None
    created_at: Optional[str] = None


class ScanHistoryItem(BaseModel):
    scan_id: str
    url: str
    verdict: str
    action: str
    risk_score: int
    reasons: List[str] = Field(default_factory=list)
    timestamp: str


class ScanHistoryResponse(BaseModel):
    scans: List[ScanHistoryItem] = Field(default_factory=list)
    total: int = 0
