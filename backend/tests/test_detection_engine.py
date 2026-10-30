import asyncio
import os
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import get_db
from app.db.database import Base
from app.db.entities import DetectionResult, URLScan
from app.main import app
from app.services.analyzer import analyze_url
from app.services.google_safe_browsing import check_google_safe_browsing
from app.services.ml_service import predict_url
from app.services.rdap_service import check_rdap
from app.services.virustotal_service import check_virustotal
from app.utils.ssrf import is_prohibited_ip, validate_target_url
from ml.feature_extractor import FEATURE_NAMES, URLFeatureExtractor

from tests.conftest import test_engine, TestingSessionLocal as TestingSession

client = TestClient(app)


# ==============================================================================
# 1. ML TESTS
# ==============================================================================

def test_feature_extractor_vector_ordering_and_length():
    extractor = URLFeatureExtractor(tld_frequencies={"com": 0.5})
    features = extractor.extract_features("https://secure.login-bank.com/auth?token=123")
    vector = extractor.extract_vector("https://secure.login-bank.com/auth?token=123")

    assert len(vector) == len(FEATURE_NAMES)
    assert len(features) == len(FEATURE_NAMES)
    assert features["IsHTTPS"] == 1
    assert features["IsDomainIP"] == 0
    assert features["NoOfObfuscatedChar"] == 1  # Hyphen count
    assert features["NoOfQmark"] == 1
    assert features["TLD_freq"] == 0.5


def test_ml_model_prediction_output_format():
    result = predict_url("https://secure-login.chase-account-verify.com/login")
    assert result["status"] in ["completed", "unavailable"]
    if result["status"] == "completed":
        assert result["prediction"] in ["phishing", "legitimate"]
        assert 0.0 <= result["confidence"] <= 1.0
        assert "PhishOFE" in result["model_name"]
        assert "model_version" in result


def test_ml_missing_model_returns_unavailable():
    with patch("app.services.ml_service.load_model", return_value=None):
        result = predict_url("https://example.com")
        assert result["status"] == "unavailable"
        assert "not found" in result["reason"].lower()


# ==============================================================================
# 2. GOOGLE SAFE BROWSING TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_google_safe_browsing_threat_detected():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL"
            }
        ]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response), \
         patch("app.core.config.settings.GOOGLE_SAFE_BROWSING_API_KEY", "mock_key"):
        result = await check_google_safe_browsing("https://malicious-phish.net")
        assert result["status"] == "completed"
        assert result["threat_detected"] is True
        assert len(result["matches"]) == 1
        assert result["matches"][0]["threat_type"] == "SOCIAL_ENGINEERING"


@pytest.mark.asyncio
async def test_google_safe_browsing_no_threat_detected():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response), \
         patch("app.core.config.settings.GOOGLE_SAFE_BROWSING_API_KEY", "mock_key"):
        result = await check_google_safe_browsing("https://clean-example.com")
        assert result["status"] == "completed"
        assert result["threat_detected"] is False
        assert len(result["matches"]) == 0


@pytest.mark.asyncio
async def test_google_safe_browsing_invalid_api_key():
    mock_response = MagicMock()
    mock_response.status_code = 400

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response), \
         patch("app.core.config.settings.GOOGLE_SAFE_BROWSING_API_KEY", "bad_key"):
        result = await check_google_safe_browsing("https://example.com")
        assert result["status"] == "unavailable"
        assert "invalid" in result["reason"].lower()


@pytest.mark.asyncio
async def test_google_safe_browsing_rate_limit_429():
    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response), \
         patch("app.core.config.settings.GOOGLE_SAFE_BROWSING_API_KEY", "mock_key"):
        result = await check_google_safe_browsing("https://example.com")
        assert result["status"] == "unavailable"
        assert "429" in result["reason"]


@pytest.mark.asyncio
async def test_google_safe_browsing_timeout():
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Timeout")), \
         patch("app.core.config.settings.GOOGLE_SAFE_BROWSING_API_KEY", "mock_key"):
        result = await check_google_safe_browsing("https://example.com")
        assert result["status"] == "unavailable"
        assert "timed out" in result["reason"].lower()


# ==============================================================================
# 3. VIRUSTOTAL TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_virustotal_completed_analysis():
    sub_resp = MagicMock()
    sub_resp.status_code = 200
    sub_resp.json.return_value = {"data": {"id": "mock_analysis_id"}}

    analysis_resp = MagicMock()
    analysis_resp.status_code = 200
    analysis_resp.json.return_value = {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 5
                }
            }
        }
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=sub_resp), \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=analysis_resp), \
         patch("app.core.config.settings.VIRUSTOTAL_API_KEY", "mock_vt_key"):
        result = await check_virustotal("https://threat-site.com")
        assert result["status"] == "completed"
        assert result["malicious"] == 3
        assert result["suspicious"] == 1
        assert result["harmless"] == 60


@pytest.mark.asyncio
async def test_virustotal_pending_analysis():
    sub_resp = MagicMock()
    sub_resp.status_code = 200
    sub_resp.json.return_value = {"data": {"id": "mock_pending_id"}}

    analysis_resp = MagicMock()
    analysis_resp.status_code = 200
    analysis_resp.json.return_value = {
        "data": {
            "attributes": {
                "status": "queued"
            }
        }
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=sub_resp), \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=analysis_resp), \
         patch("app.core.config.settings.VIRUSTOTAL_API_KEY", "mock_vt_key"):
        result = await check_virustotal("https://queued-url.org", max_retries=0)
        assert result["status"] == "pending"
        assert "in progress" in result["reason"].lower()


@pytest.mark.asyncio
async def test_virustotal_rate_limit_429():
    sub_resp = MagicMock()
    sub_resp.status_code = 429

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=sub_resp), \
         patch("app.core.config.settings.VIRUSTOTAL_API_KEY", "mock_vt_key"):
        result = await check_virustotal("https://example.com")
        assert result["status"] == "unavailable"
        assert "429" in result["reason"]


@pytest.mark.asyncio
async def test_virustotal_auth_failure():
    sub_resp = MagicMock()
    sub_resp.status_code = 401

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=sub_resp), \
         patch("app.core.config.settings.VIRUSTOTAL_API_KEY", "bad_vt_key"):
        result = await check_virustotal("https://example.com")
        assert result["status"] == "unavailable"
        assert "invalid" in result["reason"].lower()


# ==============================================================================
# 4. RDAP TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_rdap_successful_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ldhName": "example.com",
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]
            }
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}]
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        result = await check_rdap("example.com")
        assert result["status"] == "completed"
        assert result["domain"] == "example.com"
        assert result["creation_date"] == "1995-08-14T04:00:00Z"
        assert result["domain_age_days"] is not None
        assert result["domain_age_days"] > 5000
        assert result["registrar"] == "MarkMonitor Inc."


@pytest.mark.asyncio
async def test_rdap_missing_registration_date():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ldhName": "nodate.com",
        "events": [],
        "entities": []
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        result = await check_rdap("nodate.com")
        assert result["status"] == "completed"
        assert result["creation_date"] is None
        assert result["domain_age_days"] is None


@pytest.mark.asyncio
async def test_rdap_not_found_404():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        result = await check_rdap("nonexistent-unregistered-domain.xyz")
        assert result["status"] == "completed"
        assert result["registered"] is False


# ==============================================================================
# 5. COORDINATOR & DATABASE INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_coordinator_provider_failure_isolation():
    db = TestingSession()

    # One provider raises an exception, others succeed
    with patch("app.services.analyzer.check_google_safe_browsing", side_effect=Exception("Google network failure")), \
         patch("app.services.analyzer.check_virustotal", new_callable=AsyncMock, return_value={"status": "completed", "malicious": 0, "suspicious": 0, "harmless": 20, "undetected": 0}):
        response = await analyze_url("https://test-isolation.com", source="dashboard", db=db)
        assert response.status == "completed"
        assert response.checks.google_safe_browsing.status == "failed"
        assert "network failure" in response.checks.google_safe_browsing.details["reason"].lower()
        assert response.checks.virustotal.status == "completed"

    db.close()


@pytest.mark.asyncio
async def test_coordinator_google_confirmed_malicious():
    db = TestingSession()

    mock_google = {
        "status": "completed",
        "threat_detected": True,
        "matches": [{"threat_type": "SOCIAL_ENGINEERING"}]
    }

    with patch("app.services.analyzer.check_google_safe_browsing", new_callable=AsyncMock, return_value=mock_google):
        response = await analyze_url("https://phishing-threat-detected.org", db=db)
        assert response.verdict == "CRITICAL"
        assert response.risk_score == 100
        assert response.action == "BLOCK"
        assert "Google Safe Browsing confirmed a threat" in response.reason

    db.close()


@pytest.mark.asyncio
async def test_coordinator_unavailable_providers_never_produce_safe():
    db = TestingSession()

    mock_google = {"status": "unavailable", "reason": "No API key"}
    mock_vt = {"status": "unavailable", "reason": "Rate limited"}
    mock_ml = {"status": "unavailable", "reason": "ML model offline"}

    with patch("app.services.analyzer.check_google_safe_browsing", new_callable=AsyncMock, return_value=mock_google), \
         patch("app.services.analyzer.check_virustotal", new_callable=AsyncMock, return_value=mock_vt), \
         patch("app.services.analyzer.predict_url", return_value=mock_ml):
        response = await analyze_url("https://unknown-evidence.org", db=db)
        assert response.verdict == "INSUFFICIENT_EVIDENCE"
        assert response.action == "WARN"

    db.close()


@pytest.mark.asyncio
async def test_detection_results_persisted_in_database():
    db = TestingSession()

    response = await analyze_url("https://persistence-verification.org", source="extension", db=db)
    scan_id = response.scan_id

    # Verify URLScan record in SQLite
    scan_row = db.query(URLScan).filter(URLScan.scan_id == scan_id).first()
    assert scan_row is not None
    assert scan_row.original_url == "https://persistence-verification.org"
    assert scan_row.status == "completed"

    # Verify DetectionResult records in SQLite with foreign key to URLScan
    det_rows = db.query(DetectionResult).filter(DetectionResult.scan_id == scan_id).all()
    assert len(det_rows) == 5
    providers = {r.provider for r in det_rows}
    assert providers == {"ML", "Google Safe Browsing", "VirusTotal", "RDAP", "AI"}

    db.close()


# ==============================================================================
# 6. SECURITY TESTS (SSRF & SECRETS)
# ==============================================================================

def test_ssrf_rejects_localhost_and_private_ips():
    assert is_prohibited_ip("127.0.0.1") is True
    assert is_prohibited_ip("10.0.0.5") is True
    assert is_prohibited_ip("192.168.1.1") is True
    assert is_prohibited_ip("169.254.169.254") is True
    assert is_prohibited_ip("8.8.8.8") is False

    is_safe, reason = validate_target_url("http://localhost:8080/admin")
    assert is_safe is False
    assert "prohibited" in reason.lower()

    is_safe, reason = validate_target_url("http://192.168.1.1/router")
    assert is_safe is False

    is_safe, reason = validate_target_url("https://example.com")
    assert is_safe is True


def test_ssrf_rejects_unsupported_schemes():
    is_safe, reason = validate_target_url("ftp://ftp.server.com/file")
    assert is_safe is False
    assert "unsupported scheme" in reason.lower()

    is_safe, reason = validate_target_url("file:///etc/passwd")
    assert is_safe is False


# ==============================================================================
# 7. PHASE 1 & 2 FINAL STABILIZATION REGRESSION TESTS
# ==============================================================================

def test_ml_input_validation_empty_and_whitespace():
    """Verify empty and whitespace URLs are rejected before ML inference."""
    for empty_val in ["", "   ", "\t\n"]:
        res = predict_url(empty_val)
        assert res["status"] == "invalid_input"
        assert "cannot be empty" in res["reason"].lower()


def test_ml_input_validation_malformed_url():
    """Verify malformed URLs with invalid schemes or characters are rejected."""
    for bad_url in ["ht!tp://inv@lid_url", "http://", "https://"]:
        res = predict_url(bad_url)
        assert res["status"] == "invalid_input"
        assert "input validation error" in res["reason"].lower()


def test_ml_input_validation_ftp_scheme():
    """Verify unsupported schemes (e.g. FTP) are rejected before feature extraction."""
    for non_http in ["ftp://ftp.example.com/files", "file:///etc/hosts", "javascript:alert(1)"]:
        res = predict_url(non_http)
        assert res["status"] == "invalid_input"
        assert "unsupported scheme" in res["reason"].lower() or "missing url scheme" in res["reason"].lower()


def test_ml_input_validation_missing_hostname():
    """Verify URLs lacking a valid hostname are rejected before ML inference."""
    for no_host in ["http:///path/to/file", "https:///api/v1"]:
        res = predict_url(no_host)
        assert res["status"] == "invalid_input"
        assert "missing valid hostname" in res["reason"].lower()


def test_github_false_positive_remediated():
    """
    Verifies that the calibrated ML model successfully remediates the URL-only ML false positive
    on https://github.com/torvalds/linux, correctly classifying it as legitimate.
    """
    target_url = "https://github.com/torvalds/linux"
    extractor = URLFeatureExtractor()
    features = extractor.extract_features(target_url)

    # Architectural audit assertions:
    assert features["IsHTTPS"] == 1
    assert features["NoOfSubDomain"] == 0
    assert features["NoOfDots"] == 1
    assert features["URLLength"] == 33

    # Calibrated model inference classifies legitimate domain correctly
    result = predict_url(target_url)
    assert result["status"] == "completed"
    assert result["prediction"] == "legitimate"
    assert result["phishing_probability"] < 0.50


def test_risk_engine_malicious_threat_cannot_be_overridden_by_ml():
    """
    Verifies that confirmed malicious threat intelligence (Google or VirusTotal)
    CANNOT be overridden by an ML prediction of legitimate.
    """
    from app.services.risk_engine import calculate_risk

    # Case 1: Google confirmed threat, ML says legitimate
    checks_google = {
        "google_safe_browsing": {"status": "completed", "threat_detected": True},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.99},
        "rdap": {"status": "completed"}
    }
    risk_google = calculate_risk(checks_google)
    assert risk_google["verdict"] == "CRITICAL"
    assert risk_google["action"] == "BLOCK"
    assert risk_google["risk_score"] == 100

    # Case 2: VirusTotal confirmed malicious (>=2), ML says legitimate
    checks_vt = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 5, "suspicious": 1},
        "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.99},
        "rdap": {"status": "completed"}
    }
    risk_vt = calculate_risk(checks_vt)
    assert risk_vt["verdict"] == "CRITICAL"
    assert risk_vt["action"] == "BLOCK"
    assert risk_vt["risk_score"] >= 90


def test_risk_engine_missing_provider_evidence_never_safe():
    """
    Verifies that missing or unconfigured threat providers NEVER produce a false SAFE verdict.
    When providers are unavailable, the verdict MUST be INSUFFICIENT_EVIDENCE.
    """
    from app.services.risk_engine import calculate_risk

    checks_missing = {
        "google_safe_browsing": {"status": "unavailable", "reason": "No API key"},
        "virustotal": {"status": "unavailable", "reason": "No API key"},
        "ml": {"status": "completed", "prediction": "legitimate", "confidence": 0.98},
        "rdap": {"status": "completed", "domain_age_days": 5000}
    }
    risk = calculate_risk(checks_missing)
    assert risk["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert risk["action"] == "WARN"
    assert "not enough verified evidence" in risk["reason"].lower()


def test_risk_engine_invalid_ml_status_never_safe():
    """
    Verifies that when ML inference reports invalid_input or failed,
    the risk engine never evaluates the URL as SAFE.
    """
    from app.services.risk_engine import calculate_risk

    checks_invalid = {
        "google_safe_browsing": {"status": "completed", "threat_detected": False},
        "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0},
        "ml": {"status": "invalid_input", "reason": "Input validation error"},
        "rdap": {"status": "completed"}
    }
    risk = calculate_risk(checks_invalid)
    assert risk["verdict"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.asyncio
async def test_analyze_url_rejects_empty_or_invalid_syntax():
    """
    Verifies that analyze_url raises ValueError on empty or invalid URL strings
    before executing concurrent provider queries.
    """
    for invalid_target in ["", "ftp://evil.com/payload", "ht!tp://invalid", "http:///no-host"]:
        with pytest.raises(ValueError) as exc_info:
            await analyze_url(invalid_target)
        assert "Invalid URL" in str(exc_info.value)

