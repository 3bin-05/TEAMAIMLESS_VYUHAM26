import logging
import math
from typing import Any

logger = logging.getLogger("aegis")

SCORING_POLICY_VERSION = "5.1.0"


def _sanitize_float(val: Any, default: float = 0.0) -> float:
    """Ensures numeric values are valid floats without NaN or Inf."""
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except (TypeError, ValueError):
        return default


def _sanitize_int(val: Any, default: int = 0) -> int:
    """Ensures numeric values are valid non-negative integers."""
    try:
        i = int(val)
        return max(0, i)
    except (TypeError, ValueError):
        return default


def calculate_risk(checks: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluates multi-source threat intelligence using the AEGIS Deterministic
    Risk Scoring & Decision Policy (v4.0.0).

    Produces:
    - Normalized risk_score (0 - 100)
    - Categorical verdict (SAFE, SUSPICIOUS, CRITICAL, INSUFFICIENT_EVIDENCE)
    - Recommended action (ALLOW, WARN, BLOCK)
    - Categorical confidence_level (HIGH, MEDIUM, LOW)
    - Evidence completeness fraction (0.0 - 1.0)
    - Full explainability breakdown (supporting, benign, contradictory, and missing factors)
    """
    if not isinstance(checks, dict):
        logger.warning(f"calculate_risk received invalid checks argument of type {type(checks)}")
        checks = {}

    google = checks.get("google_safe_browsing") if isinstance(checks.get("google_safe_browsing"), dict) else {}
    vt = checks.get("virustotal") if isinstance(checks.get("virustotal"), dict) else {}
    ml = checks.get("ml") if isinstance(checks.get("ml"), dict) else {}
    rdap = checks.get("rdap") if isinstance(checks.get("rdap"), dict) else {}
    domain = checks.get("domain_shield") if isinstance(checks.get("domain_shield"), dict) else {}
    ai = checks.get("ai") if isinstance(checks.get("ai"), dict) else {}

    supporting_factors: list[str] = []
    benign_factors: list[str] = []
    contradictory_factors: list[str] = []
    missing_factors: list[str] = []

    # --------------------------------------------------------------------------
    # 1. CORE EVIDENCE AUDIT & COMPLETENESS ASSESSMENT
    # --------------------------------------------------------------------------
    core_provider_map = {
        "google_safe_browsing": google,
        "virustotal": vt,
        "ml": ml,
        "rdap": rdap
    }

    completed_core_count = 0
    for prov_name, prov_data in core_provider_map.items():
        if prov_data.get("status") == "completed":
            completed_core_count += 1
        else:
            status_desc = prov_data.get("status", "missing")
            missing_factors.append(f"{prov_name} was {status_desc}")

    evidence_completeness = round(completed_core_count / len(core_provider_map), 2)

    # --------------------------------------------------------------------------
    # 2. TIER 1: DETERMINISTIC THREAT INTELLIGENCE OVERRIDES (SUPREMACY)
    # --------------------------------------------------------------------------
    gsb_threat = (
        google.get("status") == "completed"
        and google.get("threat_detected") is True
    )

    vt_malicious = _sanitize_int(vt.get("malicious", 0))
    vt_suspicious = _sanitize_int(vt.get("suspicious", 0))
    vt_consensus_threat = (
        vt.get("status") == "completed"
        and vt_malicious >= 2
    )

    # Check for ML / AI contradictions against confirmed threat overrides
    ml_says_legitimate = (
        ml.get("status") == "completed"
        and ml.get("prediction") == "legitimate"
    )

    ai_analysis = ai.get("analysis") if isinstance(ai.get("analysis"), dict) else {}
    ai_recommends_allow = (
        ai.get("status") == "completed"
        and (
            ai_analysis.get("recommended_action") == "ALLOW"
            or ai_analysis.get("verdict_interpretation") == "LEGITIMATE"
        )
    )

    if gsb_threat or vt_consensus_threat:
        if ml_says_legitimate:
            contradictory_factors.append(
                "ML classifier predicted legitimate, but confirmed threat intelligence takes absolute precedence."
            )
        if ai_recommends_allow:
            contradictory_factors.append(
                "Advisory AI recommended ALLOW/safe, but confirmed threat intelligence takes absolute precedence."
            )

        if gsb_threat and vt_consensus_threat:
            supporting_factors.append("Google Safe Browsing confirmed a malicious threat.")
            supporting_factors.append(f"Multiple VirusTotal security engines ({vt_malicious}) confirmed malicious activity.")
            return {
                "verdict": "CRITICAL",
                "risk_score": 100,
                "action": "BLOCK",
                "reason": "Google Safe Browsing and VirusTotal confirmed malicious threat intelligence.",
                "confidence_level": "HIGH",
                "evidence_completeness": evidence_completeness,
                "supporting_factors": supporting_factors,
                "benign_factors": benign_factors,
                "contradictory_factors": contradictory_factors,
                "missing_factors": missing_factors,
                "policy_version": SCORING_POLICY_VERSION
            }

        if gsb_threat:
            threat_type = google.get("threat_type") or "threat"
            supporting_factors.append(f"Google Safe Browsing confirmed a threat ({threat_type}).")
            return {
                "verdict": "CRITICAL",
                "risk_score": 100,
                "action": "BLOCK",
                "reason": "Google Safe Browsing confirmed a threat.",
                "confidence_level": "HIGH",
                "evidence_completeness": evidence_completeness,
                "supporting_factors": supporting_factors,
                "benign_factors": benign_factors,
                "contradictory_factors": contradictory_factors,
                "missing_factors": missing_factors,
                "policy_version": SCORING_POLICY_VERSION
            }

        if vt_consensus_threat:
            supporting_factors.append(f"Multiple VirusTotal engines ({vt_malicious}) reported malicious activity.")
            # Tiered consensus score: 2-4 -> 90, 5-9 -> 95, 10+ -> 100
            score = 100 if vt_malicious >= 10 else (95 if vt_malicious >= 5 else 90)
            return {
                "verdict": "CRITICAL",
                "risk_score": score,
                "action": "BLOCK",
                "reason": "Multiple VirusTotal engines reported malicious activity.",
                "confidence_level": "HIGH",
                "evidence_completeness": evidence_completeness,
                "supporting_factors": supporting_factors,
                "benign_factors": benign_factors,
                "contradictory_factors": contradictory_factors,
                "missing_factors": missing_factors,
                "policy_version": SCORING_POLICY_VERSION
            }

    # --------------------------------------------------------------------------
    # 3. TIER 2: MULTI-SOURCE EVIDENCE ACCUMULATION
    # --------------------------------------------------------------------------
    score = 0

    # A. Machine Learning Heuristics
    ml_prob_valid = False
    ml_prob = 0.0
    if ml.get("status") == "completed":
        pred = str(ml.get("prediction", "")).lower()
        raw_prob = ml.get("phishing_probability")
        if raw_prob is None:
            raw_conf = ml.get("confidence")
            if raw_conf is not None:
                conf_val = _sanitize_float(raw_conf, default=-1.0)
                if 0.0 <= conf_val <= 1.0:
                    raw_prob = conf_val if pred == "phishing" else (1.0 - conf_val)
            else:
                if pred == "legitimate":
                    raw_prob = 0.0
                elif pred == "phishing":
                    raw_prob = 0.5

        # Check if raw_prob was explicitly invalid before sanitization
        try:
            val = float(raw_prob)
            if math.isnan(val) or math.isinf(val) or val < 0.0 or val > 1.0:
                prob = -1.0
            else:
                prob = val
        except (TypeError, ValueError):
            prob = -1.0

        if prob < 0.0 or prob > 1.0:
            logger.warning(f"ML provided invalid or out-of-range phishing probability: {raw_prob}")
            contradictory_factors.append(
                "ML model output contained an invalid, infinite, or missing probability value; omitted from risk score."
            )
        else:
            ml_prob_valid = True
            ml_prob = prob
            if prob < 0.50:
                # Low phishing probability: contributes 0 risk points
                if pred == "phishing":
                    contradictory_factors.append(
                        f"ML labeled URL as phishing, but probability ({prob:.1%}) is below the 0.50 threshold."
                    )
                else:
                    benign_factors.append(
                        f"Machine learning classifier classified URL structure as legitimate ({prob:.1%} phishing probability)."
                    )
            else:
                # High phishing probability (prob >= 0.50): contributes 30 to 50 risk points
                # Formula: 30 + round((prob - 0.50) * 40.0) -> scales smoothly from 30 at P=0.50 to 50 at P=1.00
                ml_contribution = int(round(30.0 + (prob - 0.50) * 40.0))
                ml_contribution = max(30, min(50, ml_contribution))
                score += ml_contribution
                supporting_factors.append(
                    f"Machine learning classifier predicted phishing with {prob:.1%} probability (+{ml_contribution} pts)."
                )
                if pred == "legitimate":
                    contradictory_factors.append(
                        f"ML labeled URL as legitimate, but raw phishing probability is elevated ({prob:.1%})."
                    )
    elif ml.get("status") in ["invalid_input", "failed", "unavailable"]:
        logger.debug(f"ML status is {ml.get('status')}; skipping ML contribution.")

    # B. VirusTotal Isolated / Suspicious Signals
    if vt.get("status") == "completed":
        if vt_malicious == 1:
            score += 25
            supporting_factors.append("Isolated VirusTotal engine flagged URL as malicious (+25 pts).")

        if vt_suspicious > 0:
            vt_susp_pts = min(vt_suspicious * 5, 15)
            score += vt_susp_pts
            supporting_factors.append(
                f"{vt_suspicious} VirusTotal engine(s) flagged URL as suspicious (+{vt_susp_pts} pts)."
            )

        if vt_malicious == 0 and vt_suspicious == 0:
            benign_factors.append("VirusTotal reported zero malicious or suspicious detections.")

    # C. Google Safe Browsing Clean Signal
    if google.get("status") == "completed" and google.get("threat_detected") is False:
        benign_factors.append("Google Safe Browsing reported zero threat detections.")

    # D. RDAP Domain Registration Intelligence
    if rdap.get("status") == "completed":
        reason = str(rdap.get("reason", "")).lower()
        is_unsupported_tld = (
            rdap.get("unsupported_tld") is True
            or "unsupported" in reason
            or "not supported" in reason
        )
        if is_unsupported_tld:
            # Unsupported TLDs do NOT count as unregistered domains!
            missing_factors.append(
                "Authoritative RDAP service does not support this top-level domain; registration status unknown."
            )
        elif rdap.get("registered") is False:
            score += 15
            supporting_factors.append("Domain is unregistered or not delegated in authoritative RDAP registry (+15 pts).")
        else:
            domain_age = rdap.get("domain_age_days")
            if domain_age is not None:
                age = _sanitize_int(domain_age, default=-1)
                if 0 <= age < 14:
                    score += 15
                    supporting_factors.append(f"Domain registered less than 14 days ago ({age} days old) (+15 pts).")
                elif 14 <= age < 30:
                    score += 10
                    supporting_factors.append(f"Domain registered less than 30 days ago ({age} days old) (+10 pts).")
                elif 30 <= age < 90:
                    score += 5
                    supporting_factors.append(f"Recent domain registration ({age} days old) (+5 pts).")
                elif age >= 365:
                    benign_factors.append(f"Established domain registration age ({age} days old).")

    # E. DomainShield Typosquatting / Impersonation (Phase 5 Active)
    if domain.get("status") == "completed":
        if domain.get("impersonation_detected") is True:
            score += 15
            matched_brand = domain.get("matched_brand") or "protected brand"
            techs = domain.get("techniques_triggered", [])
            tech_str = ", ".join(techs) if techs else "brand impersonation"
            sim = domain.get("similarity_score", 0.0)
            supporting_factors.append(
                f"DomainShield detected brand impersonation targeting {matched_brand} ({tech_str}, {sim:.0f}% similarity) (+15 pts)."
            )
        else:
            benign_factors.append("DomainShield verified domain is not impersonating known protected brands.")
    elif domain.get("status") in ["failed", "unavailable"]:
        missing_factors.append(f"domain_shield was {domain.get('status')}")

    # Bound final accumulated score
    score = max(0, min(100, score))

    # --------------------------------------------------------------------------
    # 4. CONTRADICTION & CONFIDENCE ASSESSMENT
    # --------------------------------------------------------------------------
    # Check for ML vs external intelligence contradictions
    ml_claims_phishing = (
        ml.get("status") == "completed"
        and (ml.get("prediction") == "phishing" or (ml_prob_valid and ml_prob >= 0.50))
    )
    google_clean = (
        google.get("status") == "completed"
        and google.get("threat_detected") is False
    )
    vt_clean = (
        vt.get("status") == "completed"
        and vt_malicious == 0
        and vt_suspicious == 0
    )
    rdap_established = (
        rdap.get("status") == "completed"
        and rdap.get("registered") is True
        and _sanitize_int(rdap.get("domain_age_days"), default=-1) >= 365
    )
    domain_clean_or_official = (
        domain.get("status") == "completed"
        and domain.get("impersonation_detected") is False
    )

    if ml_claims_phishing:
        if google_clean and vt_clean:
            contradictory_factors.append(
                "ML model flagged URL structure as phishing despite clean threat feeds and zero external detections."
            )
        elif google_clean and (rdap_established or domain_clean_or_official):
            age_info = f" ({rdap.get('domain_age_days')} days old)" if rdap_established else ""
            contradictory_factors.append(
                f"Machine learning classifier flagged URL structure as phishing ({ml_prob:.1%} probability), "
                f"but independent threat intelligence (Google Safe Browsing) and established domain history{age_info} "
                f"do not corroborate malicious activity."
            )

    # Determine confidence level
    if evidence_completeness == 1.0 and len(contradictory_factors) == 0:
        confidence_level = "HIGH"
    elif evidence_completeness >= 0.75:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    # --------------------------------------------------------------------------
    # 5. VERDICT AND ACTION MAPPING
    # --------------------------------------------------------------------------
    if score >= 70:
        verdict = "CRITICAL"
        action = "BLOCK"
        reason = f"High cumulative risk score ({score}/100) from multiple corroborating threat signals."
    elif score >= 30:
        verdict = "SUSPICIOUS"
        action = "WARN"
        if contradictory_factors and evidence_completeness < 1.0:
            reason = (
                f"Heuristic signals indicate elevated risk ({score}/100), but intelligence providers are contradictory "
                f"and incomplete (evidence completeness: {evidence_completeness:.0%})."
            )
        else:
            reason = f"Elevated risk detected ({score}/100) based on heuristic and intelligence indicators."
    else:
        # Score < 30: Safe criteria verification
        ml_clean = (
            ml.get("status") == "completed"
            and ml.get("prediction") == "legitimate"
            and ml_prob_valid
            and ml_prob < 0.50
        )
        # DomainShield clean verification: failed/unavailable results cannot become clean evidence
        domain_status = domain.get("status")
        if domain_status in ("failed", "unavailable"):
            domain_clean = False
        elif domain_status == "completed":
            domain_clean = (domain.get("impersonation_detected") is not True)
        else:
            domain_clean = True

        safe_checks_completed = (
            google.get("status") == "completed"
            and google.get("threat_detected") is False
            and ml_clean
            and vt.get("status") == "completed"
            and vt_malicious == 0
            and vt_suspicious == 0
            and domain_clean
            and evidence_completeness >= 0.75
        )

        if not safe_checks_completed:
            # If domain impersonation was confirmed, ensure it is classified as SUSPICIOUS/WARN
            if domain.get("impersonation_detected") is True:
                return {
                    "verdict": "SUSPICIOUS",
                    "risk_score": max(30, score),
                    "action": "WARN",
                    "reason": f"Elevated risk: DomainShield detected brand impersonation targeting {domain.get('matched_brand') or 'protected brand'}.",
                    "confidence_level": confidence_level,
                    "evidence_completeness": evidence_completeness,
                    "supporting_factors": supporting_factors,
                    "benign_factors": benign_factors,
                    "contradictory_factors": contradictory_factors,
                    "missing_factors": missing_factors,
                    "policy_version": SCORING_POLICY_VERSION
                }

            return {
                "verdict": "INSUFFICIENT_EVIDENCE",
                "risk_score": score,
                "action": "WARN",
                "reason": "There is not enough verified evidence to declare this URL safe.",
                "confidence_level": confidence_level,
                "evidence_completeness": evidence_completeness,
                "supporting_factors": supporting_factors,
                "benign_factors": benign_factors,
                "contradictory_factors": contradictory_factors,
                "missing_factors": missing_factors,
                "policy_version": SCORING_POLICY_VERSION
            }

        verdict = "SAFE"
        action = "ALLOW"
        reason = f"All core threat intelligence and machine learning checks completed clean with low observed risk ({score}/100)."

    return {
        "verdict": verdict,
        "risk_score": score,
        "action": action,
        "reason": reason,
        "confidence_level": confidence_level,
        "evidence_completeness": evidence_completeness,
        "supporting_factors": supporting_factors,
        "benign_factors": benign_factors,
        "contradictory_factors": contradictory_factors,
        "missing_factors": missing_factors,
        "policy_version": SCORING_POLICY_VERSION
    }