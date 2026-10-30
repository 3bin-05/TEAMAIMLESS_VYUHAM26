import math
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .exceptions import RiskScoringError

SIGNAL_WEIGHTS = {
    "known_malicious_match": 60,
    "virustotal_malicious": 65,
    "google_safebrowsing_threat": 70,
    "brand_impersonation_typosquat": 45,
    "allowlisted_domain": -35,
    "official_restricted_domain": -45,
    "virustotal_clean": -20,
    "certificate_verification_failed": 25,
    "hostname_mismatch": 25,
    "certificate_expired": 20,
    "direct_ip_host": 15,
    "https_to_http_downgrade": 15,
    "excessive_redirects": 10,
    "plain_http": 5,
}


@dataclass
class RiskScoreResult:
    """Internal representation of calculated risk score and evidence."""
    score: int
    source: str = "threat_intel_plus_ml"
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not (0 <= self.score <= 100):
            raise ValueError(f"Risk score must be between 0 and 100, got {self.score}")


def calculate_risk_score(
    ml_result: Dict[str, Any],
    security_signals: Optional[Union[List[Any], Dict[str, Any]]] = None,
) -> RiskScoreResult:
    """Calculate normalized risk score (0-100) combining authoritative threat intelligence
    (VirusTotal, Google Safe Browsing, live domain identity) with ML probability as secondary context.

    The validity and legitimacy of the site are grounded in ground-truth threat feeds and live
    domain identity rather than statistical ML guesses alone.
    """
    if not isinstance(ml_result, dict):
        raise RiskScoringError(
            f"Expected ml_result to be a dict, got {type(ml_result).__name__}"
        )

    if "probability" not in ml_result:
        raise RiskScoringError("ml_result dictionary is missing 'probability' field")

    raw_prob = ml_result["probability"]

    if not isinstance(raw_prob, (int, float)) or isinstance(raw_prob, bool):
        raise RiskScoringError(
            f"ML probability must be a numeric float, got {type(raw_prob).__name__}"
        )

    if math.isnan(raw_prob) or math.isinf(raw_prob):
        raise RiskScoringError(f"Invalid ML probability value: {raw_prob}")

    clamped_prob = max(0.0, min(1.0, float(raw_prob)))
    base_ml_score = round(clamped_prob * 100)

    signal_adjustment = 0
    signal_list: List[Any] = []

    if security_signals:
        if isinstance(security_signals, list):
            signal_list = security_signals
        elif isinstance(security_signals, dict) and "signals" in security_signals:
            signal_list = security_signals.get("signals", [])

        for sig in signal_list:
            sig_type = None
            if hasattr(sig, "type"):
                sig_type = sig.type
            elif isinstance(sig, dict):
                sig_type = sig.get("type")

            if sig_type and sig_type in SIGNAL_WEIGHTS:
                signal_adjustment += SIGNAL_WEIGHTS[sig_type]

    # Inspect ground-truth signals
    signal_types = {
        (getattr(s, "type", None) if hasattr(s, "type") else (s.get("type") if isinstance(s, dict) else None))
        for s in signal_list
    }

    has_threat_intel_malicious = any(
        t in signal_types
        for t in ("known_malicious_match", "virustotal_malicious", "google_safebrowsing_threat")
    )
    has_brand_impersonation = "brand_impersonation_typosquat" in signal_types
    has_trusted = any(
        t in signal_types
        for t in ("allowlisted_domain", "official_restricted_domain")
    )
    has_vt_clean = "virustotal_clean" in signal_types

    # --- DETERMINATION OF VALIDITY (Authoritative over ML heuristics) ---
    if has_threat_intel_malicious:
        # Authoritative threat intelligence match: Definitive critical threat
        final_score = max(85, min(100, 75 + signal_adjustment))
    elif has_brand_impersonation:
        # Detected lookalike / typosquat mimicking a legitimate brand
        final_score = max(70, min(95, 60 + signal_adjustment))
    elif has_trusted:
        # Official restricted TLD (.gov, .edu, etc.) or verified allowlist
        final_score = max(0, min(5, base_ml_score // 10))
    elif has_vt_clean and not has_threat_intel_malicious:
        # VirusTotal verified harmless by multiple engines and no external threat flags
        # Moderates ML false positives so authentic sites are not falsely blocked
        moderated_ml = min(base_ml_score, 25)
        final_score = max(0, min(30, moderated_ml + signal_adjustment))
    else:
        # Standard balanced calculation: ML probability combined with cybersecurity adjustments
        # When no active threat intelligence flags exist, ML cannot unilaterally exceed 65 on its own
        if not has_threat_intel_malicious and not has_brand_impersonation:
            effective_base = min(base_ml_score, 60)
            final_score = max(0, min(75, effective_base + signal_adjustment))
        else:
            final_score = max(0, min(100, base_ml_score + signal_adjustment))

    final_score = max(0, min(100, final_score))

    details = {
        "ml_probability": ml_result.get("probability"),
        "ml_prediction": ml_result.get("prediction"),
        "ml_label": ml_result.get("label"),
        "base_ml_score": base_ml_score,
        "signal_adjustment": signal_adjustment,
        "signal_count": len(signal_list),
        "threat_intel_grounded": True,
        "has_threat_intel_malicious": has_threat_intel_malicious,
        "has_brand_impersonation": has_brand_impersonation,
        "has_trusted": has_trusted,
    }

    if security_signals:
        details["security_signals"] = [
            s.to_dict() if hasattr(s, "to_dict") else s for s in signal_list
        ]

    return RiskScoreResult(score=final_score, source="threat_intel_plus_ml", details=details)
