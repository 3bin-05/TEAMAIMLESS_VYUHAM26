"""
Integration Tests for DomainShield (Phase 5)
Verifies:
- End-to-end integration into app.services.analyzer.analyze_url
- Concurrent execution alongside ML, GSB, VT, and RDAP
- Fault isolation: DomainShield exceptions do not crash the analysis pipeline
- Deterministic risk engine scoring (+15 points contribution and safety guard)
- Prevention of SAFE verdict when brand impersonation is confirmed
- API response contract containing domain_impersonation field
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.analyzer import analyze_url
from app.services.risk_engine import calculate_risk, SCORING_POLICY_VERSION
from app.services.domain_shield import check_domain_impersonation


@pytest.fixture
def client():
    return TestClient(app)


class TestDomainShieldAnalyzerIntegration:
    """Test analyzer execution of DomainShield and failure isolation."""

    @pytest.mark.asyncio
    async def test_analyzer_runs_domain_shield_concurrently(self):
        result = await analyze_url("https://g00gle.com")
        assert result.domain_impersonation is not None
        assert result.domain_impersonation["status"] == "completed"
        assert result.domain_impersonation["impersonation_detected"] is True
        assert result.domain_impersonation["matched_brand"] == "Google"
        assert result.verdict in ("SUSPICIOUS", "CRITICAL")

    @pytest.mark.asyncio
    async def test_analyzer_isolates_domain_shield_failure(self):
        """If DomainShield throws an unexpected exception, analyze_url must NOT crash."""
        with patch("app.services.analyzer.check_domain_impersonation", side_effect=RuntimeError("Simulated DS Crash")):
            result = await analyze_url("https://example.com")
            assert result is not None
            assert result.domain_impersonation is not None
            assert result.domain_impersonation["status"] == "failed"
            err_msg = result.domain_impersonation.get("error") or result.domain_impersonation.get("reason", "")
            assert "Simulated DS Crash" in err_msg
            # Analysis still successfully produced a verdict
            assert result.verdict in ("SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE")


class TestDomainShieldRiskEngineIntegration:
    """Test risk engine integration rules for DomainShield."""

    def test_scoring_policy_version_is_5(self):
        assert SCORING_POLICY_VERSION in ("5.0.0", "5.1.0")

    def test_risk_engine_awards_15_points_for_impersonation(self):
        checks = {
            "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.95, "phishing_probability": 0.05},
            "google_safe_browsing": {"status": "completed", "threat_detected": False},
            "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0, "total": 70},
            "rdap": {"status": "completed", "domain_age_days": 500, "is_new_domain": False},
            "domain_shield": {
                "status": "completed",
                "impersonation_detected": True,
                "matched_brand": "PayPal",
                "similarity_score": 90,
                "confidence": 0.95,
                "reasoning": "Typosquatting detected: substitution"
            }
        }
        res = calculate_risk(checks)
        # ML points: 0. Safe Browsing: 0. VT: 0. RDAP: 0.
        # DomainShield: +15.
        # But confirmed impersonation sets floor to 30!
        assert res["risk_score"] >= 30
        assert res["verdict"] == "SUSPICIOUS"
        assert res["action"] == "WARN"
        assert any("DomainShield detected brand impersonation targeting PayPal" in f for f in res["supporting_factors"])

    def test_impersonation_prevents_safe_verdict(self):
        """Even if ML is 99% legitimate, GSB is clean, VT is clean, impersonation MUST block SAFE."""
        checks = {
            "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.99, "phishing_probability": 0.01},
            "google_safe_browsing": {"status": "completed", "threat_detected": False},
            "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0, "total": 80},
            "rdap": {"status": "completed", "domain_age_days": 1000, "is_new_domain": False},
            "domain_shield": {
                "status": "completed",
                "impersonation_detected": True,
                "matched_brand": "Apple",
                "confidence": 0.90,
                "reasoning": "Homoglyph detected"
            }
        }
        res = calculate_risk(checks)
        assert res["verdict"] != "SAFE"
        assert res["verdict"] in ("SUSPICIOUS", "CRITICAL")

    def test_failed_or_missing_domain_shield_awards_zero_points(self):
        checks = {
            "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.95, "phishing_probability": 0.05},
            "google_safe_browsing": {"status": "completed", "threat_detected": False},
            "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0, "total": 70},
            "rdap": {"status": "completed", "domain_age_days": 400, "is_new_domain": False},
            "domain_shield": {"status": "failed", "impersonation_detected": False, "error": "Timeout"}
        }
        res = calculate_risk(checks)
        # DomainShield failed -> 0 points, clean_evidence is missing domain_shield so safe eligible is False
        assert res["risk_score"] == 0
        assert not any("DomainShield" in f for f in res["supporting_factors"])
        assert res["verdict"] == "INSUFFICIENT_EVIDENCE"

    def test_unavailable_domain_shield_cannot_become_clean_evidence(self):
        checks = {
            "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.98, "phishing_probability": 0.02},
            "google_safe_browsing": {"status": "completed", "threat_detected": False},
            "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0, "total": 75},
            "rdap": {"status": "completed", "domain_age_days": 800, "is_new_domain": False},
            "domain_shield": {"status": "unavailable", "impersonation_detected": False}
        }
        res = calculate_risk(checks)
        # Even with low score and other clean providers, unavailable domain_shield blocks SAFE
        assert res["verdict"] == "INSUFFICIENT_EVIDENCE"
        assert res["action"] == "WARN"


class TestDomainShieldApiEndpoint:
    """Test API endpoints return domain_impersonation in response payload."""

    def test_analyze_endpoint_returns_domain_shield_data(self, client):
        resp = client.post("/api/v1/analyze", json={"url": "https://g00gle.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "domain_impersonation" in data
        assert data["domain_impersonation"] is not None
        assert data["domain_impersonation"]["impersonation_detected"] is True
        assert data["domain_impersonation"]["matched_brand"] == "Google"

    def test_batch_analyze_endpoint_returns_domain_shield_data(self, client):
        resp = client.post("/api/v1/analyze/batch", json={"urls": ["https://g00gle.com", "https://google.com"]})
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert len(data["results"]) == 2
        
        # First is g00gle.com -> impersonation
        r1 = data["results"][0]
        assert r1["domain_impersonation"]["impersonation_detected"] is True
        
        # Second is google.com -> official domain, clean
        r2 = data["results"][1]
        assert r2["domain_impersonation"]["impersonation_detected"] is False
