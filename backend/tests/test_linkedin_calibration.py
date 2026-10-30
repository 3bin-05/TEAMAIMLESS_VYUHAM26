import pytest
from app.services.ml_service import predict_url
from app.services.domain_shield import check_domain_impersonation
from app.services.risk_engine import calculate_risk


# ==============================================================================
# 1. ML Classifier Calibration Tests for Bare and WWW Domains
# ==============================================================================

def test_linkedin_bare_domain_ml_prediction():
    """Verifies that https://linkedin.com/ is correctly predicted as legitimate."""
    res = predict_url("https://linkedin.com/")
    assert res["status"] == "completed"
    assert res["prediction"] == "legitimate"
    assert res["phishing_probability"] < 0.20


def test_linkedin_www_domain_ml_prediction():
    """Verifies that https://www.linkedin.com/ is correctly predicted as legitimate."""
    res = predict_url("https://www.linkedin.com/")
    assert res["status"] == "completed"
    assert res["prediction"] == "legitimate"
    assert res["phishing_probability"] < 0.20


def test_github_bare_domain_ml_prediction():
    """Verifies that https://github.com/ is correctly predicted as legitimate."""
    res = predict_url("https://github.com/")
    assert res["status"] == "completed"
    assert res["prediction"] == "legitimate"
    assert res["phishing_probability"] < 0.20


def test_google_bare_and_www_ml_prediction():
    """Verifies that Google bare and www domains are correctly predicted as legitimate."""
    for url in ["https://google.com/", "https://www.google.com/"]:
        res = predict_url(url)
        assert res["status"] == "completed"
        assert res["prediction"] == "legitimate"
        assert res["phishing_probability"] < 0.20


def test_python_org_bare_and_www_ml_prediction():
    """Verifies that python.org bare and www domains are correctly predicted as legitimate."""
    for url in ["https://python.org/", "https://www.python.org/"]:
        res = predict_url(url)
        assert res["status"] == "completed"
        assert res["prediction"] == "legitimate"
        assert res["phishing_probability"] < 0.20


# ==============================================================================
# 2. DomainShield LinkedIn Recognition Tests
# ==============================================================================

def test_domainshield_recognizes_linkedin_official_domains():
    """Verifies that DomainShield recognizes legitimate LinkedIn domains and subdomains as official."""
    official_urls = [
        "https://linkedin.com/",
        "https://www.linkedin.com/",
        "https://careers.linkedin.com/",
        "https://learning.linkedin.com/",
        "https://static.licdn.com/sc/h/al2o9zrvru7aqj8e1x2rzsrca",
        "https://lnkd.in/example"
    ]
    for url in official_urls:
        res = check_domain_impersonation(url)
        assert res["status"] == "completed"
        assert res["impersonation_detected"] is False
        assert res["matched_brand"] == "LinkedIn"
        assert "official verified domain" in res["reason"].lower()


def test_domainshield_detects_linkedin_typosquatting_and_impersonation():
    """Verifies that DomainShield actively detects typosquatting and deceptive combinations targeting LinkedIn."""
    malicious_variants = [
        ("https://linkedln.com/login", "typosquatting"),
        ("https://linkedin-verify-account.com/auth", "brand_security_keyword_composition"),
        ("https://linkedin.com.attacker-controlled.net/", "subdomain_brand_impersonation"),
    ]
    for url, expected_tech in malicious_variants:
        res = check_domain_impersonation(url)
        assert res["status"] == "completed"
        assert res["impersonation_detected"] is True
        assert res["matched_brand"] == "LinkedIn"
        assert any(expected_tech in t for t in res["techniques_triggered"])


# ==============================================================================
# 3. Missing VirusTotal and Contradiction Handling in Risk Engine
# ==============================================================================

def test_missing_virustotal_prevents_safe_verdict():
    """
    Verifies that when VirusTotal is unavailable (HTTP 429), the risk engine
    CANNOT declare the URL SAFE even if all other providers report clean/legitimate.
    Missing evidence must never become clean evidence.
    """
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "unavailable", "reason": "HTTP 429 quota exceeded"},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 8762},
        "domain_shield": {"status": "completed", "impersonation_detected": False, "matched_brand": "LinkedIn"},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.023}
    }
    verdict = calculate_risk(checks)
    assert verdict["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert verdict["action"] == "WARN"
    assert "not enough verified evidence" in verdict["reason"].lower()
    assert "virustotal was unavailable" in verdict["missing_factors"]


def test_contradictory_provider_evidence_reporting():
    """
    Verifies that when ML flags phishing but external threat intelligence and registration history
    do not corroborate that suspicion, contradictory_factors is populated and explainable reason is given.
    """
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "unavailable", "reason": "HTTP 429"},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 8762},
        "domain_shield": {"status": "completed", "impersonation_detected": False, "matched_brand": "LinkedIn"},
        "ml": {"status": "completed", "prediction": "phishing", "phishing_probability": 0.9921}
    }
    verdict = calculate_risk(checks)
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["action"] == "WARN"
    assert verdict["risk_score"] == 50
    assert len(verdict["contradictory_factors"]) >= 1
    assert "machine learning classifier flagged url structure as phishing" in verdict["contradictory_factors"][0].lower()
    assert "contradictory and incomplete" in verdict["reason"].lower()
    assert verdict["confidence_level"] == "MEDIUM"


def test_confirmed_malicious_threat_supremacy_preserved():
    """
    Verifies that confirmed malicious threat intelligence (GSB or VT) takes absolute precedence,
    even if ML predicts legitimate and DomainShield recognizes the brand.
    """
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": True, "threat_type": "MALWARE"},
        "virustotal": {"status": "completed", "malicious": 12, "suspicious": 3},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 8762},
        "domain_shield": {"status": "completed", "impersonation_detected": False, "matched_brand": "LinkedIn"},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.01}
    }
    verdict = calculate_risk(checks)
    assert verdict["verdict"] == "CRITICAL"
    assert verdict["action"] == "BLOCK"
    assert verdict["risk_score"] == 100
    assert any("confirmed threat intelligence takes absolute precedence" in f for f in verdict["contradictory_factors"])


def test_safe_verdict_eligibility_when_all_checks_clean():
    """
    Verifies that a URL only achieves SAFE verdict when ALL core checks
    (GSB, VT, RDAP, ML, and DomainShield) complete cleanly with low risk.
    """
    checks = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "rdap": {"status": "completed", "registered": True, "domain_age_days": 8762},
        "domain_shield": {"status": "completed", "impersonation_detected": False, "matched_brand": "LinkedIn"},
        "ml": {"status": "completed", "prediction": "legitimate", "phishing_probability": 0.023}
    }
    verdict = calculate_risk(checks)
    assert verdict["verdict"] == "SAFE"
    assert verdict["action"] == "ALLOW"
    assert verdict["risk_score"] == 0
    assert verdict["evidence_completeness"] == 1.0
    assert verdict["confidence_level"] == "HIGH"
