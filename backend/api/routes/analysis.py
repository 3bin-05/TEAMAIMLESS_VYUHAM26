import logging
import uuid
from datetime import datetime, timezone
from collections import deque
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from api.schemas.analysis import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    ClassificationEnum,
    UserDecisionRequest,
    UserDecisionResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
)
from api.dependencies import get_aegis_engine
from aegis_engine import AegisEngine, AnalysisResult
from aegis_engine.exceptions import EngineError

logger = logging.getLogger("aegis.api")

router = APIRouter(prefix="/api/v1", tags=["Analysis"])

# In-memory storage for recent scans and user decisions (for UI history)
_MAX_HISTORY = 200
_history_items: deque = deque(maxlen=_MAX_HISTORY)
_scans_by_id: Dict[str, AnalyzeResponse] = {}


def _build_frontend_checks(result: AnalysisResult) -> Dict[str, Any]:
    """Transform backend internal signals into the structured checks format expected by UI."""
    signals = result.signals or {}
    cyber = signals.get("cyber_analysis", {})
    threat_intel = cyber.get("threat_intel", {}).get("data", {}) if isinstance(cyber.get("threat_intel"), dict) else {}

    # 1. ML Model Check
    ml_prob = float(signals.get("ml_probability", 0.0) or 0.0)
    ml_check = {
        "status": "completed",
        "prediction": str(signals.get("ml_label", result.classification)).lower(),
        "confidence": round(1.0 - ml_prob if ml_prob < 0.5 else ml_prob, 2),
        "phishing_probability": round(ml_prob, 4),
        "model_version": result.model_version,
        "features_used": 16,
    }

    # 2. Google Safe Browsing Check
    sb_data = threat_intel.get("safe_browsing", {}) if isinstance(threat_intel, dict) else {}
    sb_available = sb_data.get("available", False)
    sb_check = {
        "status": "completed" if sb_available else "no_match",
        "threat_detected": sb_data.get("is_threat", False),
        "threat_type": ", ".join(sb_data.get("threat_types", [])) if sb_data.get("threat_types") else None,
        "match_count": len(sb_data.get("matches", []) or []),
        "details": sb_data,
    }

    # 3. VirusTotal Check
    vt_data = threat_intel.get("virustotal", {}) if isinstance(threat_intel, dict) else {}
    vt_status = "completed" if vt_data.get("available") else ("error" if vt_data.get("status") == "http_error_429" else "no_match")
    vt_check = {
        "status": vt_status,
        "malicious": vt_data.get("malicious", 0),
        "suspicious": vt_data.get("suspicious", 0),
        "harmless": vt_data.get("harmless", 0),
        "undetected": vt_data.get("undetected", 0),
        "reason": vt_data.get("error"),
        "details": vt_data,
    }

    # 4. Live RDAP Domain Registration Check
    rdap_section = cyber.get("rdap", {}) if isinstance(cyber, dict) else {}
    rdap_data = rdap_section.get("data", {}) if isinstance(rdap_section, dict) else {}
    dns_section = cyber.get("dns", {}) if isinstance(cyber, dict) else {}
    dns_data = dns_section.get("data", {}) if isinstance(dns_section, dict) else {}

    rdap_status = "completed" if rdap_data.get("registered") else ("unavailable" if not rdap_section.get("available") else "no_match")
    rdap_check = {
        "status": rdap_status,
        "domain": rdap_data.get("domain") or dns_data.get("hostname", ""),
        "registered": rdap_data.get("registered", dns_data.get("resolved", False)),
        "registrar": rdap_data.get("registrar"),
        "creation_date": rdap_data.get("registration_date"),
        "registration_date": rdap_data.get("registration_date"),
        "expiration_date": rdap_data.get("expiration_date"),
        "domain_age_days": rdap_data.get("domain_age_days"),
        "nameservers": rdap_data.get("nameservers") or dns_data.get("a_records", []),
        "status_codes": rdap_data.get("status_codes", []),
        "details": {
            **rdap_data,
            "nameservers": dns_data.get("a_records", []),
            "privacy_redacted": rdap_data.get("privacy_redacted", False),
        },
    }

    # 5. DomainShield Check
    lookalike_data = threat_intel.get("brand_lookalike") if isinstance(threat_intel, dict) else None
    has_lookalike = bool(lookalike_data and isinstance(lookalike_data, dict))
    domain_shield = {
        "status": "completed",
        "is_lookalike": has_lookalike,
        "impersonation_detected": has_lookalike,
        "matched_brand": lookalike_data.get("brand") if has_lookalike else None,
        "official_domain": lookalike_data.get("official_domain") if has_lookalike else None,
        "official_target_domain": lookalike_data.get("official_domain") if has_lookalike else None,
        "similarity_score": lookalike_data.get("confidence") if has_lookalike else None,
        "details": lookalike_data if has_lookalike else {},
    }

    # 6. Local AI Check
    ai_data = result.ai or {}
    ai_avail = ai_data.get("available", False)
    ai_check = {
        "status": "completed" if ai_avail else ("unavailable" if not ai_data else str(ai_data.get("status", "unavailable"))),
        "provider": ai_data.get("provider", "ollama"),
        "model": ai_data.get("model", "qwen3:4b-instruct"),
        "explanation": ai_data.get("summary"),
        "latency_ms": ai_data.get("latency_ms"),
        "details": ai_data,
    }

    # 7. Web History & AEO Presence
    wh_section = cyber.get("web_history", {}) if isinstance(cyber, dict) else {}
    wh_data = wh_section.get("data", {}) if isinstance(wh_section, dict) else {}

    return {
        "ml": ml_check,
        "google_safe_browsing": sb_check,
        "virustotal": vt_check,
        "rdap": rdap_check,
        "domain_shield": domain_shield,
        "ai": ai_check,
        "web_history": wh_data,
    }


def _build_ai_explanation(ai_data: Optional[Dict[str, Any]], classification: str) -> Optional[Dict[str, Any]]:
    """Build structured AIExplanation compatible with ThreatReport and VerdictCard."""
    if not ai_data or not ai_data.get("available"):
        return None

    raw_findings = ai_data.get("key_findings", [])
    reasons = [
        {
            "title": f"Key Finding {i + 1}",
            "explanation": str(f),
            "source": "local_ai",
            "severity": "high" if classification in ("MALICIOUS", "CRITICAL") else "medium",
        }
        for i, f in enumerate(raw_findings)
    ]

    return {
        "risk_level": (ai_data.get("final_verdict") or classification).lower(),
        "summary": ai_data.get("summary") or ai_data.get("risk_assessment") or "",
        "reasons": reasons,
        "anomalies": [
            {"title": "Signal", "explanation": s, "source": "signal_correlator"}
            for s in ai_data.get("supporting_signals", [])
        ],
        "similar_sites": [],
    }


def _build_domain_impersonation(result: AnalysisResult) -> Optional[Dict[str, Any]]:
    """Extract domain impersonation details from threat intel signals."""
    signals = result.signals or {}
    cyber = signals.get("cyber_analysis", {})
    threat_intel = cyber.get("threat_intel", {}).get("data", {}) if isinstance(cyber.get("threat_intel"), dict) else {}
    lookalike = threat_intel.get("brand_lookalike") if isinstance(threat_intel, dict) else None

    if lookalike and isinstance(lookalike, dict):
        return {
            "status": "completed",
            "is_lookalike": True,
            "impersonation_detected": True,
            "matched_brand": lookalike.get("brand"),
            "official_domain": lookalike.get("official_domain"),
            "official_target_domain": lookalike.get("official_domain"),
            "similarity_score": lookalike.get("confidence"),
            "details": lookalike,
        }
    return None


def _run_analysis(payload: AnalyzeRequest, engine: AegisEngine) -> AnalyzeResponse:
    """Shared analysis logic for both /analyze and /analyze-url endpoints."""
    logger.info(f"Received analysis request for URL length {len(payload.url)}")

    # Execute Aegis Engine pipeline (with multi-tier fallback protection)
    result: AnalysisResult = engine.analyze(payload.url)

    # Validate risk score range strictly (0 <= risk_score <= 100)
    risk_score = result.risk_score if isinstance(result.risk_score, int) else 50
    risk_score = max(0, min(100, risk_score))

    # Normalize verdict to strictly SAFE, SUSPICIOUS, MALICIOUS
    raw_class = str(result.classification).upper()
    if raw_class in ("CRITICAL", "MALICIOUS"):
        classification_enum = ClassificationEnum.MALICIOUS
    elif raw_class == "SUSPICIOUS":
        classification_enum = ClassificationEnum.SUSPICIOUS
    else:
        classification_enum = ClassificationEnum.SAFE

    # Policy action mapping
    if classification_enum == ClassificationEnum.SAFE:
        action = "ALLOW"
    elif classification_enum == ClassificationEnum.SUSPICIOUS:
        action = "WARN"
    else:
        action = "BLOCK"

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Build rich UI contracts
    checks = _build_frontend_checks(result)
    ai_explanation = _build_ai_explanation(result.ai, classification_enum.value)
    domain_impersonation = _build_domain_impersonation(result)
    primary_reason = result.reasons[0] if result.reasons else f"Risk Score: {risk_score}/100"
    is_fallback = bool(result.signals.get("fallback_mode") or result.signals.get("ai_fallback", {}).get("active"))

    response = AnalyzeResponse(
        url=result.url,
        normalized_url=result.url,
        classification=classification_enum,
        risk_score=risk_score,
        reasons=result.reasons,
        signals=result.signals,
        ai=result.ai,
        model_version=result.model_version,
        cached=result.cached,
        analysis_time_ms=result.analysis_time_ms,
        scan_id=scan_id,
        action=action,
        status="completed",
        verdict=classification_enum.value,
        created_at=now_iso,
        checks=checks,
        domain_impersonation=domain_impersonation,
        ai_explanation=ai_explanation,
        confidence_level="HIGH" if not is_fallback else "MEDIUM",
        reason=primary_reason,
        fallback_triggered=is_fallback,
    )

    # Record in history (synchronized with response)
    history_entry = ScanHistoryItem(
        scan_id=scan_id,
        url=result.url,
        verdict=classification_enum.value,
        action=action,
        risk_score=risk_score,
        reasons=result.reasons or [],
        timestamp=now_iso,
    )
    _history_items.appendleft(history_entry)
    _scans_by_id[scan_id] = response

    return response


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Primary URL security analysis endpoint",
    description="Analyzes a target URL for phishing threats using ML classification, cybersecurity analysis, and advisory local AI.",
)
def analyze_url(
    payload: AnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> AnalyzeResponse:
    """Analyze input URL and return structured security classification and signals."""
    return _run_analysis(payload, engine)


@router.post(
    "/analyze-url",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias URL security analysis endpoint",
    description="Backward-compatible alias for POST /api/v1/analyze.",
    include_in_schema=True,
)
def analyze_url_alias(
    payload: AnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> AnalyzeResponse:
    """Alias endpoint — delegates to the same analysis pipeline as /analyze."""
    return _run_analysis(payload, engine)


@router.post(
    "/analyze-batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch URL security analysis endpoint",
    description="Analyzes multiple URLs in batch for search engine result annotations and real-time page scanning.",
)
@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def analyze_batch(
    payload: BatchAnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> BatchAnalyzeResponse:
    """Analyze a batch of URLs concurrently or sequentially and return verified results."""
    results: list[AnalyzeResponse] = []
    seen = set()
    for raw_url in payload.urls:
        url_str = (raw_url or "").strip()
        if not url_str or url_str in seen:
            continue
        seen.add(url_str)
        try:
            req = AnalyzeRequest(url=url_str)
            res = _run_analysis(req, engine)
            results.append(res)
        except Exception as err:
            logger.warning(f"Batch item analysis failed for {url_str}: {err}")
            continue

    return BatchAnalyzeResponse(results=results, total=len(results))


@router.get(
    "/history",
    response_model=ScanHistoryResponse,
    summary="List recent URL scans history",
    description="Returns the list of recently performed scans for the dashboard history view.",
)
def get_scan_history() -> ScanHistoryResponse:
    """Return recent scan history items."""
    scans = list(_history_items)
    return ScanHistoryResponse(scans=scans, total=len(scans))


@router.get(
    "/history/{scan_id}",
    response_model=AnalyzeResponse,
    summary="Get details for a specific scan ID",
    description="Retrieves the detailed scan response for a given scan_id from recent history.",
)
def get_scan_history_detail(scan_id: str) -> AnalyzeResponse:
    """Return specific scan details by ID."""
    if scan_id in _scans_by_id:
        return _scans_by_id[scan_id]
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan ID '{scan_id}' not found.")


@router.get(
    "/status/{scan_id}",
    summary="Check scan completion status",
)
def get_scan_status(scan_id: str) -> dict:
    """Status probe for scans."""
    if scan_id in _scans_by_id:
        return {"scan_id": scan_id, "status": "completed", "progress": 100}
    return {"scan_id": scan_id, "status": "not_found", "progress": 0}


@router.get(
    "/verdict/{scan_id}",
    response_model=AnalyzeResponse,
    summary="Retrieve verdict by scan ID",
)
def get_verdict(scan_id: str) -> AnalyzeResponse:
    """Return verdict details for a scan ID."""
    if scan_id in _scans_by_id:
        return _scans_by_id[scan_id]
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Verdict for scan '{scan_id}' not found.")


@router.post(
    "/decisions",
    response_model=UserDecisionResponse,
    summary="Record user proceeding or canceling decision",
)
def record_user_decision(payload: UserDecisionRequest) -> UserDecisionResponse:
    """Record user override/decision from warning screen or extension."""
    logger.info(f"User decision recorded: scan={payload.scan_id}, decision={payload.decision}")
    now_iso = datetime.now(timezone.utc).isoformat()
    return UserDecisionResponse(
        status="recorded",
        scan_id=payload.scan_id,
        decision=payload.decision,
        created_at=now_iso,
    )
