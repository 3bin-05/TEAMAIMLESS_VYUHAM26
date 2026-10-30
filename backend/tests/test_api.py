import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import get_db
from app.db.database import Base
from app.db.entities import URLScan, UserDecision, DetectionResult
from app.main import app
from app.schemas.analysis import (
    AnalyzeResponse,
    BatchAnalyzeResponse,
    DecisionResponse,
    HealthResponse,
    ScanDetailResponse,
)

from tests.conftest import test_engine, TestingSessionLocal, override_get_db

client = TestClient(app)


# 1. Root endpoint returns HTTP 200
def test_root_endpoint_returns_200():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["app_name"] == "AEGIS"
    assert "docs_url" in data


# 2. Health endpoint returns HTTP 200
def test_health_endpoint_returns_200():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    validated = HealthResponse(**data)
    assert validated.status == "healthy"
    assert validated.app_name == "AEGIS"
    assert validated.environment == "development"


# 3. Analyze request validation works (valid request)
def test_analyze_request_validation_works():
    payload = {
        "url": "https://secure-login.paypal-verification.com/account",
        "source": "extension"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    validated = AnalyzeResponse(**data)
    assert validated.status == "completed"
    assert validated.verdict in ["SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE"]
    assert validated.scan_id is not None
    assert validated.checks.ml.status in ["completed", "unavailable", "failed"]


# 4. Invalid URL requests are rejected
def test_invalid_url_requests_are_rejected():
    response = client.post("/api/v1/analyze", json={"url": "not-a-valid-http-url"})
    assert response.status_code == 422
    data = response.json()
    assert data.get("error_type") == "validation_error" or "detail" in data or "details" in data


# 5. Batch requests enforce the 20-URL maximum
def test_batch_requests_enforce_20_maximum():
    # Valid batch within limit (5 URLs)
    valid_urls = [f"https://example{i}.com" for i in range(5)]
    valid_resp = client.post("/api/v1/analyze/batch", json={"urls": valid_urls})
    assert valid_resp.status_code == 200
    batch_data = valid_resp.json()
    validated = BatchAnalyzeResponse(**batch_data)
    assert validated.status == "completed"
    assert validated.count == 5

    # Excess batch (21 URLs exceeds max_length=20)
    excess_urls = [f"https://example{i}.com" for i in range(21)]
    excess_resp = client.post("/api/v1/analyze/batch", json={"urls": excess_urls})
    assert excess_resp.status_code == 422

    # Empty batch (0 URLs fails min_length=1)
    empty_resp = client.post("/api/v1/analyze/batch", json={"urls": []})
    assert empty_resp.status_code == 422


# 6. History endpoint returns a valid response
def test_history_endpoint_returns_valid_response():
    # First add a scan
    client.post("/api/v1/analyze", json={"url": "https://example.com/login", "source": "dashboard"})

    response = client.get("/api/v1/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["domain"] == "example.com"


# 7. Missing scan IDs return HTTP 404
def test_missing_scan_id_returns_404():
    non_existent_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/history/{non_existent_id}")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in (data.get("message") or data.get("detail", "")).lower()


# 8. Decision validation works
def test_decision_validation_works():
    # Create a scan first
    create_resp = client.post("/api/v1/analyze", json={"url": "https://suspicious-domain.com"})
    scan_id = create_resp.json()["scan_id"]

    # Submit valid PROCEED decision
    proceed_resp = client.post("/api/v1/decisions", json={"scan_id": scan_id, "decision": "PROCEED"})
    assert proceed_resp.status_code == 200
    decision_data = proceed_resp.json()
    validated = DecisionResponse(**decision_data)
    assert validated.decision == "PROCEED"
    assert validated.status == "saved"

    # Submit invalid decision string
    invalid_resp = client.post("/api/v1/decisions", json={"scan_id": scan_id, "decision": "INVALID_CHOICE"})
    assert invalid_resp.status_code == 422


# 9. Decisions for nonexistent scans are rejected
def test_decisions_for_nonexistent_scans_are_rejected():
    non_existent_id = str(uuid.uuid4())
    response = client.post("/api/v1/decisions", json={"scan_id": non_existent_id, "decision": "CANCEL"})
    assert response.status_code == 404


# 10. Database records can be created and retrieved
def test_database_records_can_be_created_and_retrieved():
    db = TestingSessionLocal()
    scan_id = str(uuid.uuid4())

    new_scan = URLScan(
        scan_id=scan_id,
        original_url="https://test-record.com",
        normalized_url="https://test-record.com/",
        domain="test-record.com",
        status="pending",
        source="extension",
        verdict="INSUFFICIENT_EVIDENCE"
    )
    db.add(new_scan)
    db.commit()

    retrieved = db.query(URLScan).filter(URLScan.scan_id == scan_id).first()
    assert retrieved is not None
    assert retrieved.domain == "test-record.com"
    assert retrieved.status == "pending"

    # Add detection result linked via foreign key
    result = DetectionResult(
        result_id=str(uuid.uuid4()),
        scan_id=scan_id,
        provider="ML",
        status="completed",
        result_data={"prediction": "safe", "confidence": 0.95}
    )
    db.add(result)
    db.commit()

    assert len(retrieved.detection_results) == 1
    assert retrieved.detection_results[0].provider == "ML"
    db.close()


# 11. API responses follow the agreed schemas
def test_api_responses_follow_agreed_schemas():
    # Analyze response schema check
    analyze_resp = client.post("/api/v1/analyze", json={"url": "https://secure-portal.net"})
    assert analyze_resp.status_code == 200
    analyze_model = AnalyzeResponse(**analyze_resp.json())
    assert analyze_model.scan_id is not None
    assert analyze_model.verdict in ["SAFE", "SUSPICIOUS", "CRITICAL", "INSUFFICIENT_EVIDENCE"]

    # Scan detail response schema check
    detail_resp = client.get(f"/api/v1/history/{analyze_model.scan_id}")
    assert detail_resp.status_code == 200
    detail_model = ScanDetailResponse(**detail_resp.json())
    assert detail_model.scan_id == analyze_model.scan_id
    assert detail_model.original_url.rstrip("/") == "https://secure-portal.net"


# 12. Test database isolation verification
def test_test_database_isolation():
    assert test_engine.url.database == ":memory:"
    assert app.dependency_overrides[get_db] == override_get_db
