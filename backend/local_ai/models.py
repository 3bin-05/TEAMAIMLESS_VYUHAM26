from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


class AIStatus:
    SUCCESS = "success"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MODEL_NOT_FOUND = "model_not_found"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_ERROR = "provider_error"


@dataclass
class AIAnalysisResult:
    """Structured output from Local AI security signal correlation.

    final_verdict and final_score are the LLM's authoritative classification decision.
    When populated (available=True), they override the deterministic pipeline's verdict.
    """
    available: bool = False
    status: str = AIStatus.DISABLED
    provider: str = "none"
    model: str = "none"
    summary: str = ""
    risk_assessment: str = ""
    key_findings: List[str] = field(default_factory=list)
    supporting_signals: List[str] = field(default_factory=list)
    conflicting_signals: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    # LLM-authoritative final verdict and score (overrides deterministic pipeline)
    final_verdict: Optional[str] = None   # "SAFE" | "SUSPICIOUS" | "CRITICAL"
    final_score: Optional[int] = None     # 0-100 risk score as judged by LLM
    latency_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)



@dataclass
class AIContext:
    """Controlled, serializable security context passed to Local AI."""
    url: str
    ml_signal: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    classification: str = "SAFE"
    dns_signals: Dict[str, Any] = field(default_factory=dict)
    http_signals: Dict[str, Any] = field(default_factory=dict)
    tls_signals: Dict[str, Any] = field(default_factory=dict)
    redirect_signals: Dict[str, Any] = field(default_factory=dict)
    threat_intel_signals: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
