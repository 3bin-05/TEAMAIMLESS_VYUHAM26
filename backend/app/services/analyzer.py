import asyncio
from datetime import datetime, timezone
import logging
from urllib.parse import urlsplit
import uuid
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.entities import DetectionResult, URLScan
from app.schemas.analysis import (
    AnalysisChecks,
    AnalyzeResponse,
    CheckResult,
)
from app.services.content_inspector import inspect_safe_content
from app.services.domain_shield import check_domain_impersonation
from app.services.google_safe_browsing import check_google_safe_browsing
from app.services.ml_anomalies import extract_technical_anomalies
from app.services.ml_service import predict_url
from app.services.rdap_service import check_rdap
from app.services.risk_engine import calculate_risk
from app.services.virustotal_service import check_virustotal
from app.utils.url import extract_domain, normalize_url, validate_url_syntax

logger = logging.getLogger("aegis")


def _safe_provider_result(result: any, provider_name: str) -> dict:
    """Wraps caught exceptions or invalid results into a structured failure dictionary."""
    if isinstance(result, Exception):
        logger.warning(f"Provider '{provider_name}' raised an unhandled exception: {result}")
        return {
            "status": "failed",
            "reason": str(result)
        }
    if not isinstance(result, dict):
        return {
            "status": "failed",
            "reason": f"Provider '{provider_name}' returned invalid non-dict response"
        }
    return result


async def analyze_url(
    url: str,
    source: str = "extension",
    allow_cloud_ai: bool | None = None,
    db: Session | None = None
) -> AnalyzeResponse:
    """
    Coordinates multi-source phishing intelligence analysis:
    - Validates URL syntax and rejects empty, malformed, or non-HTTP/HTTPS URLs.
    - Normalizes URL and extracts domain.
    - Concurrently queries ML, Google Safe Browsing, VirusTotal, RDAP, DomainShield, and safe content inspection.
    - Submits gathered evidence to Local Ollama LLM as authoritative cyber threat analyst.
    - The LLM synthesizes evidence, explains findings, and generates the final verdict.
    - Persists provider results to DetectionResult and records URLScan in SQLite.
    """
    raw_url = str(url).strip()
    is_valid, validation_err = validate_url_syntax(raw_url)
    if not is_valid:
        raise ValueError(f"Invalid URL: {validation_err}")

    normalized = normalize_url(raw_url)
    domain = extract_domain(normalized)

    if not domain:
        raise ValueError(f"Invalid URL: could not extract valid domain from '{raw_url}'")

    scan_id = str(uuid.uuid4())

    # Concurrently gather all 6 intelligence providers with exception isolation
    ml_task = asyncio.to_thread(predict_url, normalized)
    google_task = check_google_safe_browsing(normalized)
    vt_task = check_virustotal(normalized)
    rdap_task = check_rdap(domain)
    domain_shield_task = asyncio.to_thread(check_domain_impersonation, normalized)
    content_task = inspect_safe_content(normalized)

    ml_res, google_res, vt_res, rdap_res, ds_res, content_res = await asyncio.gather(
        ml_task,
        google_task,
        vt_task,
        rdap_task,
        domain_shield_task,
        content_task,
        return_exceptions=True
    )

    safe_ml = _safe_provider_result(ml_res, "ML")
    safe_google = _safe_provider_result(google_res, "Google Safe Browsing")
    safe_vt = _safe_provider_result(vt_res, "VirusTotal")
    safe_rdap = _safe_provider_result(rdap_res, "RDAP")
    safe_ds = _safe_provider_result(ds_res, "DomainShield")
    safe_content = _safe_provider_result(content_res, "Content Inspector")

    checks = {
        "ml": safe_ml,
        "google_safe_browsing": safe_google,
        "virustotal": safe_vt,
        "rdap": safe_rdap,
        "domain_shield": safe_ds,
        "content_inspector": safe_content,
        "ai": {"status": "not_run", "details": {}}
    }

    # Extract technical anomalies from ML features and URL structure
    ml_features = safe_ml.get("features", {}) if isinstance(safe_ml, dict) else {}
    tech_anomalies = extract_technical_anomalies(normalized, ml_features)

    # Execute Hybrid / Local AI Intelligence Layer (Phase 15 Evidence Dossier)
    try:
        from app.services.ai.ai_router import router as ai_router
        from app.services.ai.ai_schemas import AIEvidenceInput

        ai_evidence = AIEvidenceInput(
            url=normalized,
            domain=domain,
            ml_status=checks["ml"].get("status"),
            ml_prediction=checks["ml"].get("prediction"),
            ml_confidence=checks["ml"].get("confidence"),
            google_status=checks["google_safe_browsing"].get("status"),
            google_threat_detected=checks["google_safe_browsing"].get("threat_detected"),
            google_threat_types=[checks["google_safe_browsing"].get("threat_type")] if checks["google_safe_browsing"].get("threat_type") else [],
            virustotal_status=checks["virustotal"].get("status"),
            virustotal_malicious=int(checks["virustotal"].get("malicious", 0) or 0),
            virustotal_suspicious=int(checks["virustotal"].get("suspicious", 0) or 0),
            virustotal_harmless=int(checks["virustotal"].get("harmless", 0) or 0),
            rdap_status=checks["rdap"].get("status"),
            domain_age_days=checks["rdap"].get("domain_age_days"),
            registrar=checks["rdap"].get("registrar"),
            domain_shield_status=checks["domain_shield"].get("status"),
            domain_impersonation_detected=checks["domain_shield"].get("impersonation_detected", False),
            domain_matched_brand=checks["domain_shield"].get("matched_brand"),
            content_status=safe_content.get("status", "completed"),
            content_title=safe_content.get("title"),
            content_meta_description=safe_content.get("meta_description"),
            has_login_form=safe_content.get("has_login_form", False),
            has_password_field=safe_content.get("has_password_field", False),
            content_suspicious_patterns=safe_content.get("suspicious_patterns", []),
            technical_anomalies=tech_anomalies
        )

        ai_res = await ai_router.analyze(ai_evidence, allow_cloud_ai=allow_cloud_ai)
        checks["ai"] = {
            "status": ai_res.status,
            "provider": ai_res.provider,
            "model": ai_res.model,
            "is_cloud": ai_res.is_cloud,
            "latency_ms": ai_res.latency_ms,
            "explanation": ai_res.raw_explanation,
            "analysis": ai_res.analysis.model_dump() if ai_res.analysis else None,
            "error_reason": ai_res.error_reason
        }
    except Exception as ai_exc:
        logger.warning(f"AI intelligence layer encountered an unexpected exception: {ai_exc}")
        checks["ai"] = {
            "status": "failed",
            "provider": "none",
            "model": "none",
            "is_cloud": False,
            "error_reason": str(ai_exc)
        }

    # Evaluate deterministic baseline for telemetry and fail-safe fallback
    risk = calculate_risk(checks)

    # Phase 15: Synthesize Local Ollama LLM intelligence with evidence-driven baseline
    final_verdict = risk["verdict"]
    final_action = risk["action"]
    final_risk_score = risk["risk_score"]
    final_reason = risk["reason"]
    final_confidence = risk.get("confidence_level", "LOW")

    if checks["ai"].get("status") == "completed" and checks["ai"].get("analysis"):
        ai_data = checks["ai"]["analysis"]
        risk_level = str(ai_data.get("risk_level", "")).lower().strip()
        recommendation = str(ai_data.get("recommendation", "")).lower().strip()

        # If AI detects malicious threats or advises blocking, elevate to CRITICAL / BLOCK
        if risk_level == "malicious" or recommendation == "block":
            final_verdict = "CRITICAL"
            final_action = "BLOCK"
            final_risk_score = max(final_risk_score, 90)
            if ai_data.get("summary") and "Mock AI" not in ai_data.get("summary", ""):
                final_reason = ai_data["summary"]
        elif risk_level == "suspicious" or recommendation == "warn":
            if final_verdict != "CRITICAL":
                final_verdict = "SUSPICIOUS"
                final_action = "WARN"
                final_risk_score = max(final_risk_score, 60)
                if ai_data.get("summary") and "Mock AI" not in ai_data.get("summary", ""):
                    final_reason = ai_data["summary"]
        elif risk_level == "safe" or recommendation == "allow":
            # AI confirms safe when no deterministic critical threats or impersonation are detected
            if final_verdict not in ("CRITICAL", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"):
                final_verdict = "SAFE"
                final_action = "ALLOW"
                final_risk_score = min(final_risk_score, 20)
                if ai_data.get("summary") and "Mock AI" not in ai_data.get("summary", ""):
                    final_reason = ai_data["summary"]

        if final_verdict in ("SAFE", "CRITICAL"):
            final_confidence = "HIGH"
        else:
            final_confidence = "MEDIUM"

    # Check object structured for Pydantic response
    checks_obj = AnalysisChecks(
        ml=CheckResult(
            status=checks["ml"].get("status", "unavailable"),
            details=checks["ml"]
        ),
        google_safe_browsing=CheckResult(
            status=checks["google_safe_browsing"].get("status", "unavailable"),
            details=checks["google_safe_browsing"]
        ),
        virustotal=CheckResult(
            status=checks["virustotal"].get("status", "unavailable"),
            details=checks["virustotal"]
        ),
        rdap=CheckResult(
            status=checks["rdap"].get("status", "unavailable"),
            details=checks["rdap"]
        ),
        ai=CheckResult(
            status=checks["ai"].get("status", "not_run"),
            details=checks["ai"]
        ),
        domain_shield=CheckResult(
            status=checks["domain_shield"].get("status", "not_run"),
            details=checks["domain_shield"]
        )
    )

    ai_explanation_payload = None
    if checks["ai"].get("analysis"):
        ai_explanation_payload = {
            "provider": checks["ai"].get("provider"),
            "model": checks["ai"].get("model"),
            "is_cloud": checks["ai"].get("is_cloud"),
            "latency_ms": checks["ai"].get("latency_ms"),
            **checks["ai"]["analysis"]
        }
    elif checks["ai"].get("explanation"):
        ai_explanation_payload = {
            "provider": checks["ai"].get("provider"),
            "model": checks["ai"].get("model"),
            "is_cloud": checks["ai"].get("is_cloud"),
            "explanation": checks["ai"].get("explanation")
        }

    decision_payload = {
        "summary": final_reason,
        "verdict": final_verdict,
        "risk_score": final_risk_score,
        "action": final_action,
        "confidence_level": final_confidence,
        "evidence_completeness": risk.get("evidence_completeness"),
        "supporting_factors": risk.get("supporting_factors", []),
        "benign_factors": risk.get("benign_factors", []),
        "contradictory_factors": risk.get("contradictory_factors", []),
        "missing_factors": risk.get("missing_factors", []),
        "policy_version": risk.get("policy_version", "5.0.0")
    }

    response = AnalyzeResponse(
        scan_id=scan_id,
        url=raw_url,
        normalized_url=normalized,
        status="completed",
        verdict=final_verdict,
        risk_score=final_risk_score,
        action=final_action,
        reason=final_reason,
        checks=checks_obj,
        domain_impersonation=checks["domain_shield"],
        ai_explanation=ai_explanation_payload,
        confidence_level=final_confidence,
        evidence_completeness=risk.get("evidence_completeness"),
        decision_details=decision_payload,
        timestamp=datetime.now(timezone.utc)
    )

    # Database persistence
    if db is not None:
        try:
            persisted_checks = dict(checks)
            persisted_checks["decision"] = decision_payload

            # 1. Create URLScan record
            scan_record = URLScan(
                scan_id=scan_id,
                original_url=raw_url,
                normalized_url=normalized,
                domain=domain,
                verdict=final_verdict,
                risk_score=final_risk_score,
                action=final_action,
                reason=final_reason,
                source=source,
                status="completed",
                checks=persisted_checks
            )
            db.add(scan_record)

            # 2. Persist individual DetectionResult records for each provider
            provider_mapping = [
                ("ML", checks["ml"]),
                ("Google Safe Browsing", checks["google_safe_browsing"]),
                ("VirusTotal", checks["virustotal"]),
                ("RDAP", checks["rdap"]),
                ("AI", checks["ai"])
            ]

            for prov_name, prov_data in provider_mapping:
                det_record = DetectionResult(
                    result_id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    provider=prov_name,
                    status=prov_data.get("status", "unknown"),
                    result_data=prov_data
                )
                db.add(det_record)

            db.commit()
            logger.info(f"Persisted scan {scan_id} and {len(provider_mapping)} detection results to database.")
        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to persist scan {scan_id} to database: {exc}")

    return response