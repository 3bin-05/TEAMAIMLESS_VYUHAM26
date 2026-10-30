import math
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.risk_engine import calculate_risk, SCORING_POLICY_VERSION
from app.services.analyzer import analyze_url

client = TestClient(app)


# ==============================================================================
# 1. RISK SCORE BOUNDARIES & DETERMINISTIC REPEATABILITY
# ==============================================================================

def test_risk_score_minimum_and_maximum_bounds():
    """Verify risk scores never exceed [0, 100] even with extreme inputs."""
    # Negative / empty checks
    res_min = calculate_risk({})
    assert 0 <= res_min["risk_score"] <= 100

    # Over-accumulated checks (ML + VT + RDAP + Shield + high suspicious)
    extreme_checks = {
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 1.0},
        "virustotal": {"status": "completed", "malicious": 1, "suspicious": 100},
        "rdap": {"status": "completed", "domain_age_days": 1, "registered": False},
        "domain_shield": {"status": "completed", "possible_match": {"similarity": 99}}
    }
    res_max = calculate_risk(extreme_checks)
    assert res_max["risk_score"] <= 100
    assert res_max["risk_score"] >= 70
    assert res_max["verdict"] == "CRITICAL"
    assert res_max["action"] == "BLOCK"


def test_risk_score_deterministic_repeatability():
    """Verify identical inputs across 100 executions produce strictly identical outputs."""
    sample_checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 1, "suspicious": 2},
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.88},
        "rdap": {"status": "completed", "domain_age_days": 20, "registered": True}
    }

    first_result = calculate_risk(sample_checks)
    for _ in range(100):
        subsequent = calculate_risk(sample_checks)
        assert subsequent == first_result


def test_risk_score_threshold_boundaries():
    """Verify exact verdict transitions at score thresholds 30 and 70."""
    # Score 29 -> below 30 threshold (cannot be safe if missing threat providers)
    checks_low = {
        "google_safe_browsing": {"status": "unavailable"},
        "virustotal": {"status": "completed", "malicious": 1},  # +25 pts
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "unavailable"}
    }
    res_low = calculate_risk(checks_low)
    assert res_low["risk_score"] == 25
    assert res_low["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert res_low["action"] == "WARN"

    # Score 30 -> SUSPICIOUS threshold
    checks_susp = {
        "google_safe_browsing": {"status": "unavailable"},
        "virustotal": {"status": "completed", "malicious": 1, "suspicious": 1},  # 25 + 5 = 30 pts
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "unavailable"}
    }
    res_susp = calculate_risk(checks_susp)
    assert res_susp["risk_score"] == 30
    assert res_susp["verdict"] == "SUSPICIOUS"
    assert res_susp["action"] == "WARN"

    # Score >= 70 -> CRITICAL threshold without override
    checks_crit = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 1, "suspicious": 1},  # 25 + 5 = 30 pts
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.99},  # +50 pts
        "rdap": {"status": "completed", "domain_age_days": 500}  # 0 pts
    }
    res_crit = calculate_risk(checks_crit)
    assert res_crit["risk_score"] == 80  # 30 + 50 = 80
    assert res_crit["verdict"] == "CRITICAL"
    assert res_crit["action"] == "BLOCK"


def test_invalid_and_nan_inputs_sanitized():
    """Verify NaN, Inf, negative, and malformed inputs do not crash calculation."""
    malformed_checks = {
        "google_safe_browsing": "not_a_dict",
        "virustotal": {"status": "completed", "malicious": -10, "suspicious": float("nan")},
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": float("inf")},
        "rdap": {"status": "completed", "domain_age_days": "unknown"}
    }
    res = calculate_risk(malformed_checks)
    assert isinstance(res["risk_score"], int)
    assert 0 <= res["risk_score"] <= 100
    assert res["verdict"] in ["SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE"]


# ==============================================================================
# 2. THREAT OVERRIDES & SUPREMACY
# ==============================================================================

def test_google_safe_browsing_threat_override_always_critical():
    """Verify confirmed GSB threats force score 100, CRITICAL, and BLOCK."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": True, "threat_type": "MALWARE"},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.99},
        "rdap": {"status": "completed", "domain_age_days": 4000}
    }
    res = calculate_risk(checks)
    assert res["verdict"] == "CRITICAL"
    assert res["action"] == "BLOCK"
    assert res["risk_score"] == 100
    assert "Google Safe Browsing confirmed a threat" in res["reason"]
    assert any("precedence" in c.lower() for c in res["contradictory_factors"])


def test_virustotal_consensus_threat_override():
    """Verify VirusTotal malicious consensus (>=2) triggers CRITICAL override."""
    # 2 detections -> score 90
    checks_2 = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 2, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_2 = calculate_risk(checks_2)
    assert res_2["verdict"] == "CRITICAL"
    assert res_2["action"] == "BLOCK"
    assert res_2["risk_score"] == 90

    # 5 detections -> score 95
    checks_5 = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 5, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_5 = calculate_risk(checks_5)
    assert res_5["risk_score"] == 95

    # 12 detections -> score 100
    checks_12 = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 12, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_12 = calculate_risk(checks_12)
    assert res_12["risk_score"] == 100


def test_both_gsb_and_vt_threat_override_coexistence():
    """Verify concurrent threats from both GSB and VT produce combined explanation and score 100."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": True},
        "virustotal": {"status": "completed", "malicious": 8, "suspicious": 2},
        "ml": {"status": "completed", "prediction": "phishing"},
        "rdap": {"status": "completed"}
    }
    res = calculate_risk(checks)
    assert res["verdict"] == "CRITICAL"
    assert res["risk_score"] == 100
    assert res["action"] == "BLOCK"
    assert "Google Safe Browsing and VirusTotal confirmed" in res["reason"]


def test_ai_allow_cannot_downgrade_threat():
    """Verify advisory AI recommending ALLOW cannot downgrade confirmed threat."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": True},
        "virustotal": {"status": "completed", "malicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed"},
        "ai": {
            "status": "completed",
            "analysis": {
                "verdict_interpretation": "LEGITIMATE",
                "recommended_action": "ALLOW"
            }
        }
    }
    res = calculate_risk(checks)
    assert res["verdict"] == "CRITICAL"
    assert res["action"] == "BLOCK"
    assert res["risk_score"] == 100
    assert any("Advisory AI recommended ALLOW" in c for c in res["contradictory_factors"])


# ==============================================================================
# 3. MACHINE LEARNING HEURISTIC EVIDENCE
# ==============================================================================

def test_ml_phishing_probability_scaling():
    """Verify ML phishing prediction contributes scaled points based on probability."""
    # High probability 0.95 -> 48-50 points
    checks_high = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.95},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_high = calculate_risk(checks_high)
    assert res_high["risk_score"] >= 45
    assert res_high["verdict"] == "SUSPICIOUS"
    assert res_high["action"] == "WARN"

    # Missing ML status does not crash and contributes 0 points
    checks_missing = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "failed", "reason": "Timeout"},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_missing = calculate_risk(checks_missing)
    assert res_missing["risk_score"] == 0
    assert res_missing["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_ml_bare_domain_false_positive_contradiction_detection():
    """Verify bare-domain false-positive ML prediction is noted in contradictory_factors."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.98},
        "rdap": {"status": "completed", "domain_age_days": 2000}
    }
    res = calculate_risk(checks)
    assert any("ML model flagged URL structure as phishing despite clean threat feeds" in c for c in res["contradictory_factors"])


# ==============================================================================
# 4. VIRUSTOTAL DETECTIONS & ENGINE THRESHOLDS
# ==============================================================================

def test_virustotal_single_malicious_and_suspicious_accumulation():
    """Verify single malicious detection (+25) and suspicious detections (+5 each up to 15)."""
    # 1 malicious + 2 suspicious = 25 + 10 = 35 points
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 1, "suspicious": 2},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 500}
    }
    res = calculate_risk(checks)
    assert res["risk_score"] == 35
    assert res["verdict"] == "SUSPICIOUS"
    assert res["action"] == "WARN"


def test_virustotal_pending_and_unavailable_states():
    """Verify pending or unavailable VT evidence does not add risk points and blocks SAFE."""
    checks_pending = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "pending", "malicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 500}
    }
    res_pending = calculate_risk(checks_pending)
    assert res_pending["risk_score"] == 0
    assert res_pending["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any("virustotal was pending" in m for m in res_pending["missing_factors"])


# ==============================================================================
# 5. RDAP DOMAIN AGE INTELLIGENCE
# ==============================================================================

def test_rdap_domain_age_tiers():
    """Verify RDAP domain age increments: <14d (+15), <30d (+10), <90d (+5), >=365d (+0)."""
    def check_age(days):
        return calculate_risk({
            "google_safe_browsing": {"status": "completed", "threat_detected": False},
            "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
            "ml": {"status": "completed", "prediction": "legitimate"},
            "rdap": {"status": "completed", "domain_age_days": days}
        })

    # < 14 days -> 15 pts, verdict INSUFFICIENT_EVIDENCE or SAFE?
    # Because score < 30 and all 3 threat detectors are clean, let's verify:
    res_7d = check_age(7)
    assert res_7d["risk_score"] == 15
    assert any("less than 14 days" in s for s in res_7d["supporting_factors"])

    # < 30 days -> 10 pts
    res_20d = check_age(20)
    assert res_20d["risk_score"] == 10

    # < 90 days -> 5 pts
    res_60d = check_age(60)
    assert res_60d["risk_score"] == 5

    # >= 365 days -> 0 pts
    res_500d = check_age(500)
    assert res_500d["risk_score"] == 0
    assert any("Established domain" in b for b in res_500d["benign_factors"])


def test_rdap_unregistered_domain():
    """Verify domain flagged as unregistered in RDAP adds +15 points."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "registered": False}
    }
    res = calculate_risk(checks)
    assert res["risk_score"] == 15
    assert any("Domain is unregistered" in s for s in res["supporting_factors"])


# ==============================================================================
# 6. EVIDENCE COMPLETENESS & CONFIDENCE LEVELS
# ==============================================================================

def test_evidence_completeness_and_confidence_classification():
    """Verify completeness fraction and categorical confidence levels (HIGH, MEDIUM, LOW)."""
    # All 4 core completed and clean -> 1.0, HIGH, SAFE
    checks_all = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }
    res_all = calculate_risk(checks_all)
    assert res_all["evidence_completeness"] == 1.0
    assert res_all["confidence_level"] == "HIGH"
    assert res_all["verdict"] == "SAFE"
    assert res_all["action"] == "ALLOW"

    # 3 of 4 core completed (RDAP unavailable) -> 0.75, MEDIUM, SAFE (since all 3 threat detectors are clean)
    checks_3 = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "unavailable"}
    }
    res_3 = calculate_risk(checks_3)
    assert res_3["evidence_completeness"] == 0.75
    assert res_3["confidence_level"] == "MEDIUM"
    assert res_3["verdict"] == "SAFE"

    # 2 of 4 core completed -> 0.5, LOW, INSUFFICIENT_EVIDENCE
    checks_2 = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "unavailable"},
        "ml": {"status": "completed", "prediction": "legitimate"},
        "rdap": {"status": "unavailable"}
    }
    res_2 = calculate_risk(checks_2)
    assert res_2["evidence_completeness"] == 0.5
    assert res_2["confidence_level"] == "LOW"
    assert res_2["verdict"] == "INSUFFICIENT_EVIDENCE"


# ==============================================================================
# 7. EXPLAINABLE DECISION DETAILS & API INTEGRATION
# ==============================================================================

@pytest.mark.asyncio
async def test_analyzer_endpoint_returns_decision_details():
    """Verify POST /api/v1/analyze includes decision_details and confidence fields in response."""
    response = client.post("/api/v1/analyze", json={"url": "https://paypal-verification-test.com"})
    assert response.status_code == 200
    data = response.json()

    assert "verdict" in data
    assert "risk_score" in data
    assert "confidence_level" in data
    assert "evidence_completeness" in data
    assert "decision_details" in data

    details = data["decision_details"]
    assert details is not None
    assert "summary" in details
    assert "verdict" in details
    assert "risk_score" in details
    assert "supporting_factors" in details
    assert "benign_factors" in details
    assert "policy_version" in details
    assert details["policy_version"] == SCORING_POLICY_VERSION


@pytest.mark.asyncio
async def test_batch_analyze_consistency_with_single_analyze():
    """Verify batch analyze produces the identical deterministic score and verdict as single analyze."""
    url = "https://paypal-batch-consistency-test.com"

    single_resp = client.post("/api/v1/analyze", json={"url": url})
    assert single_resp.status_code == 200
    single_data = single_resp.json()

    batch_resp = client.post("/api/v1/analyze/batch", json={"urls": [url]})
    assert batch_resp.status_code == 200
    batch_data = batch_resp.json()

    assert batch_data["count"] == 1
    batch_item = batch_data["results"][0]

    assert batch_item["verdict"] == single_data["verdict"]
    assert batch_item["risk_score"] == single_data["risk_score"]
    assert batch_item["action"] == single_data["action"]
    assert batch_item["confidence_level"] == single_data["confidence_level"]


# ==============================================================================
# 8. FOCUSED AUDIT & MATHEMATICAL FORMULA VERIFICATION TESTS
# ==============================================================================

def test_ml_probability_gradient_and_boundaries():
    """
    Verifies that low phishing probabilities (0.00, 0.01, 0.10, 0.25) contribute 0 pts,
    and probabilities >= 0.50 scale smoothly from 30 to 50 pts without triggering CRITICAL alone.
    """
    base_clean = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }

    # P = 0.00 -> 0 pts, SAFE
    res_00 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.00}})
    assert res_00["risk_score"] == 0
    assert res_00["verdict"] == "SAFE"
    assert res_00["action"] == "ALLOW"

    # P = 0.01 -> 0 pts, SAFE
    res_01 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.01}})
    assert res_01["risk_score"] == 0
    assert res_01["verdict"] == "SAFE"

    # P = 0.10 -> 0 pts, SAFE
    res_10 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.10}})
    assert res_10["risk_score"] == 0
    assert res_10["verdict"] == "SAFE"

    # P = 0.25 -> 0 pts, SAFE
    res_25 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.25}})
    assert res_25["risk_score"] == 0
    assert res_25["verdict"] == "SAFE"

    # P = 0.50 -> 30 pts (enters SUSPICIOUS band)
    res_50 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.50}})
    assert res_50["risk_score"] == 30
    assert res_50["verdict"] == "SUSPICIOUS"
    assert res_50["action"] == "WARN"

    # P = 0.75 -> 40 pts
    res_75 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.75}})
    assert res_75["risk_score"] == 40
    assert res_75["verdict"] == "SUSPICIOUS"
    assert res_75["action"] == "WARN"

    # P = 0.90 -> 46 pts
    res_90 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.90}})
    assert res_90["risk_score"] == 46
    assert res_90["verdict"] == "SUSPICIOUS"

    # P = 0.99 -> 50 pts
    res_99 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.99}})
    assert res_99["risk_score"] == 50
    assert res_99["verdict"] == "SUSPICIOUS"

    # P = 1.00 -> 50 pts (Capped at 50; ML alone NEVER reaches CRITICAL threshold 70)
    res_100 = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 1.00}})
    assert res_100["risk_score"] == 50
    assert res_100["verdict"] == "SUSPICIOUS"
    assert res_100["action"] == "WARN"


def test_ml_invalid_nan_infinite_and_missing_probabilities():
    """Verify NaN, Inf, out-of-range, and missing ML probabilities are sanitized and prevent false SAFE."""
    base_clean = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }

    # NaN probability
    res_nan = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": float("nan")}})
    assert res_nan["risk_score"] == 0
    assert res_nan["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any("invalid, infinite, or missing probability" in c for c in res_nan["contradictory_factors"])

    # Infinite probability
    res_inf = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": float("inf")}})
    assert res_inf["risk_score"] == 0
    assert res_inf["verdict"] == "INSUFFICIENT_EVIDENCE"

    # Negative probability
    res_neg = calculate_risk({**base_clean, "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": -0.5}})
    assert res_neg["risk_score"] == 0
    assert res_neg["verdict"] == "INSUFFICIENT_EVIDENCE"

    # ML unavailable
    res_unavail = calculate_risk({**base_clean, "ml": {"status": "unavailable"}})
    assert res_unavail["risk_score"] == 0
    assert res_unavail["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_domainshield_zero_points_in_phase_4():
    """Verify DomainShield contributes 0 risk points in Phase 4 even if status is completed."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.05},
        "rdap": {"status": "completed", "domain_age_days": 500},
        "domain_shield": {"status": "completed", "possible_match": {"similarity": 95, "target_brand": "paypal"}}
    }
    res = calculate_risk(checks)
    # Score must be 0 because DomainShield is not active in Phase 4
    assert res["risk_score"] == 0
    assert res["verdict"] == "SAFE"


def test_rdap_timeout_and_network_failure_contribute_zero_points():
    """Verify RDAP query timeouts and network failures do not add arbitrary risk points."""
    # Timeout -> status: "unavailable"
    checks_timeout = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.02},
        "rdap": {"status": "unavailable", "reason": "RDAP query timed out"}
    }
    res_timeout = calculate_risk(checks_timeout)
    assert res_timeout["risk_score"] == 0
    assert any("rdap was unavailable" in m for m in res_timeout["missing_factors"])

    # Network failure -> status: "failed"
    checks_failed = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.02},
        "rdap": {"status": "failed", "reason": "Connection refused"}
    }
    res_failed = calculate_risk(checks_failed)
    assert res_failed["risk_score"] == 0
    assert any("rdap was failed" in m for m in res_failed["missing_factors"])


def test_rdap_unsupported_tld_does_not_count_as_unregistered():
    """Verify unsupported ccTLDs/gTLDs do not get penalized as unregistered domains (+15)."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.05},
        "rdap": {
            "status": "completed",
            "registered": False,
            "unsupported_tld": True,
            "reason": "TLD not supported by IANA RDAP bootstrap"
        }
    }
    res = calculate_risk(checks)
    # Must NOT add 15 points
    assert res["risk_score"] == 0
    assert any("does not support this top-level domain" in m for m in res["missing_factors"])


def test_rdap_missing_registration_date_contributes_zero_points():
    """Verify missing creation/registration dates remain unknown and contribute 0 pts."""
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.02},
        "rdap": {
            "status": "completed",
            "registered": True,
            "domain_age_days": None,
            "creation_date": None
        }
    }
    res = calculate_risk(checks)
    assert res["risk_score"] == 0
    assert res["verdict"] == "SAFE"


def test_safe_verdict_reproducibility():
    """Verify realistic clean multi-source scenarios consistently reproduce SAFE/ALLOW."""
    # Scenario 1: Clean banking domain
    s1 = calculate_risk({
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.005},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 5400, "registrar": "CSC Corporate Domains"}
    })
    assert s1["verdict"] == "SAFE"
    assert s1["action"] == "ALLOW"
    assert s1["risk_score"] == 0
    assert s1["confidence_level"] == "HIGH"
    assert s1["evidence_completeness"] == 1.0

    # Scenario 2: Clean educational domain with 0.12 ML prob
    s2 = calculate_risk({
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.12},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 3200, "registrar": "Educause"}
    })
    assert s2["verdict"] == "SAFE"
    assert s2["action"] == "ALLOW"
    assert s2["risk_score"] == 0
    assert s2["confidence_level"] == "HIGH"


def test_missing_evidence_strictly_prevents_safe():
    """Verify missing any core provider strictly prevents an unsupported SAFE verdict."""
    clean_base = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.01},
        "rdap": {"status": "completed", "domain_age_days": 1000}
    }

    # Missing Google
    r_g = calculate_risk({**clean_base, "google_safe_browsing": {"status": "unavailable"}})
    assert r_g["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert r_g["action"] == "WARN"

    # Missing VirusTotal
    r_vt = calculate_risk({**clean_base, "virustotal": {"status": "unavailable"}})
    assert r_vt["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert r_vt["action"] == "WARN"

    # Missing ML
    r_ml = calculate_risk({**clean_base, "ml": {"status": "unavailable"}})
    assert r_ml["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert r_ml["action"] == "WARN"

    # All unavailable
    r_all = calculate_risk({
        "google_safe_browsing": {"status": "unavailable"},
        "virustotal": {"status": "unavailable"},
        "ml": {"status": "unavailable"},
        "rdap": {"status": "unavailable"}
    })
    assert r_all["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert r_all["risk_score"] == 0

