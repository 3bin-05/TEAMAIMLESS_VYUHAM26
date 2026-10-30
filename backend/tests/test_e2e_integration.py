import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.analysis import (
    AnalyzeResponse,
    BatchAnalyzeResponse,
    ScanDetailResponse,
    DecisionResponse,
    HealthResponse,
)
from app.services.ai.ai_schemas import AIStatusResponse
from app.utils.ssrf import validate_target_url

client = TestClient(app)


class TestE2EIntegrationPipeline:
    """Complete End-to-End System Integration Tests for AEGIS Phase 6."""

    def test_e2e_health_and_ai_status(self):
        """Verifies health and AI status endpoints behave reliably and without secrets."""
        health_resp = client.get("/api/v1/health")
        assert health_resp.status_code == 200
        health = HealthResponse(**health_resp.json())
        assert health.status == "healthy"
        assert health.app_name == "AEGIS"
        assert health.environment == "development"

        ai_resp = client.get("/api/v1/ai/status")
        assert ai_resp.status_code == 200
        ai_data = AIStatusResponse(**ai_resp.json())
        assert ai_data.mode in ["AUTO", "LOCAL_ONLY", "CLOUD_ONLY", "DISABLED"]
        # Claude key must never be leaked
        assert "api_key" not in str(ai_resp.json())
        assert "sk-ant" not in str(ai_resp.json())

    def test_e2e_url_scan_persistence_and_retrieval(self):
        """Tests full cycle: scan URL -> verify response -> retrieve in history -> fetch full details."""
        test_url = "https://legitimate-service-portal.com/dashboard"
        analyze_resp = client.post("/api/v1/analyze", json={
            "url": test_url,
            "source": "dashboard",
            "allow_cloud_ai": False
        })
        assert analyze_resp.status_code == 200
        result = AnalyzeResponse(**analyze_resp.json())
        assert result.scan_id is not None
        assert result.status == "completed"
        assert result.risk_score >= 0 and result.risk_score <= 100
        assert result.verdict in ["SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE"]

        # Verify history reflects the new scan
        history_resp = client.get("/api/v1/history?limit=10")
        assert history_resp.status_code == 200
        history_items = history_resp.json()
        assert any(item["scan_id"] == result.scan_id for item in history_items)

        # Verify full scan detail retrieval
        detail_resp = client.get(f"/api/v1/history/{result.scan_id}")
        assert detail_resp.status_code == 200
        detail = ScanDetailResponse(**detail_resp.json())
        assert detail.scan_id == result.scan_id
        assert detail.original_url == test_url
        assert detail.verdict == result.verdict
        assert detail.risk_score == result.risk_score
        assert detail.checks is not None

    def test_e2e_user_decision_recording(self):
        """Verifies recording user override decision (PROCEED / CANCEL) for a scan."""
        # First scan a URL
        analyze_resp = client.post("/api/v1/analyze", json={
            "url": "https://suspicious-test-auth-portal.com/login",
            "source": "extension"
        })
        scan_id = analyze_resp.json()["scan_id"]

        # User chooses to proceed anyway
        decision_resp = client.post("/api/v1/decisions", json={
            "scan_id": scan_id,
            "decision": "PROCEED"
        })
        assert decision_resp.status_code == 200
        decision_data = DecisionResponse(**decision_resp.json())
        assert decision_data.scan_id == scan_id
        assert decision_data.decision == "PROCEED"
        assert decision_data.status == "saved"

    def test_e2e_batch_analyze_searchguard_compatibility(self):
        """Verifies batch analysis handles SearchGuard search-result payloads correctly."""
        batch_urls = [
            "https://www.google.com/search?q=test",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://paypa1-account-security-alert.com/login",
            "https://github.com/microsoft/vscode"
        ]
        batch_resp = client.post("/api/v1/analyze/batch", json={
            "urls": batch_urls,
            "source": "searchguard"
        })
        assert batch_resp.status_code == 200
        batch_data = BatchAnalyzeResponse(**batch_resp.json())
        assert batch_data.count == 4
        assert len(batch_data.results) == 4
        for item in batch_data.results:
            assert item["scan_id"] is not None
            assert item["status"] == "completed"
            assert item["verdict"] in ["SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE"]

    def test_e2e_batch_size_limit_enforced(self):
        """Verifies that batch endpoint enforces max batch limit (20 URLs)."""
        too_many_urls = [f"https://domain{i}.com" for i in range(25)]
        batch_resp = client.post("/api/v1/analyze/batch", json={
            "urls": too_many_urls,
            "source": "searchguard"
        })
        assert batch_resp.status_code == 422

    def test_e2e_domainshield_brand_impersonation_detection(self):
        """Verifies DomainShield catches typo/lookalike brand impersonation in end-to-end scan."""
        impersonation_url = "https://paypa1-security-verification.com/login"
        resp = client.post("/api/v1/analyze", json={
            "url": impersonation_url,
            "source": "extension"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["domain_shield"]["status"] == "completed"
        assert data["domain_impersonation"]["impersonation_detected"] is True
        assert data["domain_impersonation"]["matched_brand"] == "PayPal"
        # Impersonation must elevate risk score to SUSPICIOUS or CRITICAL
        assert data["verdict"] in ["SUSPICIOUS", "CRITICAL"]
        assert data["risk_score"] >= 45

    def test_e2e_official_brand_domain_not_flagged(self):
        """Verifies official domain for protected brand is recognized as official and safe."""
        official_url = "https://www.paypal.com/signin"
        resp = client.post("/api/v1/analyze", json={
            "url": official_url,
            "source": "extension"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["domain_shield"]["status"] == "completed"
        assert data["domain_impersonation"]["impersonation_detected"] is False
        assert "Official" in data["domain_impersonation"]["reasoning"]

    def test_e2e_invalid_url_and_ssrf_rejection(self):
        """Verifies invalid schemes and malformed inputs are rejected by API, and SSRF validator rejects private IPs."""
        # API boundary rejection
        invalid_inputs = [
            "ftp://files.example.com",
            "javascript:alert(1)",
            "not_a_valid_url",
            ""
        ]
        for bad_url in invalid_inputs:
            resp = client.post("/api/v1/analyze", json={"url": bad_url, "source": "test"})
            assert resp.status_code in [400, 422], f"URL {bad_url} was not rejected appropriately!"

        # SSRF validation utility rejection
        ssrf_targets = [
            "http://127.0.0.1:8000/admin",
            "http://localhost:5173",
            "http://192.168.1.1/router",
            "http://10.0.0.1/internal"
        ]
        for target in ssrf_targets:
            is_safe, reason = validate_target_url(target)
            assert not is_safe, f"SSRF target {target} should have been rejected!"
            assert "prohibited" in reason.lower() or "ssrf" in reason.lower()

    def test_e2e_nonexistent_scan_id_returns_404(self):
        """Verifies retrieving a nonexistent scan_id returns clean 404."""
        resp = client.get("/api/v1/history/non-existent-scan-id-9999")
        assert resp.status_code == 404
        assert "not found" in resp.json()["message"].lower()
