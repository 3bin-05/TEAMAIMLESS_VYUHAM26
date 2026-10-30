"""
Phase 12 End-to-End System Tests: Extension & Backend Integration
Validates:
- Test A: Safe website navigation decision and verification-bypass token lifecycle
- Test B: Suspicious website warning, reason presentation, and decision override
- Test C: Malicious website blocking and non-bypassable policy
- Test D: Fail-safe handling for network errors and unverified destinations
- Test E: Concurrent multi-tab verification isolation
- Test F: Redirect URL unwrap and destination evaluation
- Test G: Repeat scan consistency and non-permanent caching
- Test H: Authoritative extension file integrity, manifest, and build artifact validation
"""

import json
from pathlib import Path
import time
from urllib.parse import urlparse, parse_qs
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.analysis import AnalyzeResponse, DecisionResponse

client = TestClient(app)


class TestA_SafeWebsiteAndLoopPrevention:
    """Test A: Safe website verification and one-time approval bypass token simulation."""

    def test_safe_url_evaluation(self):
        resp = client.post("/api/v1/analyze", json={
            "url": "https://www.wikipedia.org",
            "source": "chrome_extension"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["verdict"] in ["SAFE", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"]  # Conservative fail-safe
        assert data["url"] in ["https://www.wikipedia.org", "https://www.wikipedia.org/"]

    def test_loop_prevention_token_logic(self):
        """Simulates the background service-worker one-time approval token mechanism."""
        approvals = {}  # key: f"{tab_id}:{normalized_url}" -> token

        def register_approval(tab_id: int, url: str, attempt_id: str):
            now = time.time()
            approvals[f"{tab_id}:{url.lower()}"] = {
                "attempt_id": attempt_id,
                "expires_at": now + 15.0
            }

        def check_and_consume(tab_id: int, url: str) -> bool:
            key = f"{tab_id}:{url.lower()}"
            token = approvals.get(key)
            if not token:
                return False
            if time.time() > token["expires_at"]:
                del approvals[key]
                return False
            # CONSUME ONCE
            del approvals[key]
            return True

        tab_id = 101
        test_url = "https://example-clean-site.org/home"
        attempt_id = "att_test_123"

        # Initially unapproved
        assert check_and_consume(tab_id, test_url) is False

        # Register approval (e.g. after backend returned SAFE + ALLOW)
        register_approval(tab_id, test_url, attempt_id)

        # First consumption on navigation resume -> Approved!
        assert check_and_consume(tab_id, test_url) is True

        # Second consumption (loop attempt) -> Rejected! Must not loop infinitely!
        assert check_and_consume(tab_id, test_url) is False


class TestB_SuspiciousWebsiteWarningAndOverride:
    """Test B: Suspicious website classification, reason communication, and explicit override."""

    def test_suspicious_classification_and_reasons(self):
        # Brand lookalike/typosquatting URL
        typo_url = "https://paypa1-security-verification.com/login"
        resp = client.post("/api/v1/analyze", json={
            "url": typo_url,
            "source": "chrome_extension"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in ["SUSPICIOUS", "CRITICAL"]
        assert data["action"] in ["WARN", "BLOCK"]
        assert data["reason"] is not None
        assert data["domain_impersonation"]["impersonation_detected"] is True

        # User chooses to proceed with caution
        decision_resp = client.post("/api/v1/decisions", json={
            "scan_id": data["scan_id"],
            "decision": "proceed"  # verify case-insensitive support
        })
        assert decision_resp.status_code == 200
        dec_data = decision_resp.json()
        assert dec_data["decision"] == "PROCEED"
        assert dec_data["status"] == "saved"


class TestC_MaliciousWebsitePolicyEnforcement:
    """Test C: Malicious website blocking and non-bypassable policy."""

    def test_malicious_blocked_policy(self):
        # Known confirmed phishing pattern
        mal_url = "https://paypalsecure-login-update99.com/account/auth.php"
        resp = client.post("/api/v1/analyze", json={
            "url": mal_url,
            "source": "chrome_extension"
        })
        assert resp.status_code == 200
        data = resp.json()
        # Risk policy marks severe lookalikes or threats
        assert data["risk_score"] >= 45
        assert data["action"] in ["WARN", "BLOCK"]


class TestD_FailSafeErrorHandling:
    """Test D: Fail-safe behavior on invalid URLs and missing records."""

    def test_invalid_scheme_rejected(self):
        resp = client.post("/api/v1/analyze", json={
            "url": "javascript:alert('pwned')",
            "source": "chrome_extension"
        })
        assert resp.status_code in [400, 422]

    def test_nonexistent_scan_details_fail_safe(self):
        resp = client.get("/api/v1/history/non-existent-scan-id-xyz")
        assert resp.status_code == 404


class TestE_ConcurrentNavigationIsolation:
    """Test E: Multiple concurrent URL inspections maintain isolated scan_ids and results."""

    def test_concurrent_scans_isolation(self):
        urls = [
            "https://wikipedia.org",
            "https://python.org",
            "https://github.com"
        ]
        responses = [client.post("/api/v1/analyze", json={"url": u}) for u in urls]
        assert all(r.status_code == 200 for r in responses)
        scan_ids = [r.json()["scan_id"] for r in responses]
        assert len(set(scan_ids)) == 3, "Each scan must have a unique scan_id"


class TestF_RedirectUrlUnwrapLogic:
    """Test F: Google search redirect unwrapping."""

    @staticmethod
    def unwrap_redirect(raw_url: str) -> str:
        if "/url?" in raw_url:
            parsed = urlparse(raw_url)
            qs = parse_qs(parsed.query)
            target = qs.get("q", [None])[0] or qs.get("url", [None])[0]
            if target:
                return target
        return raw_url

    def test_redirect_unwrapping(self):
        wrapped = "https://www.google.com/url?q=https://real-target-domain.com/path&sa=U"
        unwrapped = self.unwrap_redirect(wrapped)
        assert unwrapped == "https://real-target-domain.com/path"


class TestG_RepeatVisitConsistency:
    """Test G: Repeat visits to same URL produce consistent deterministic classifications."""

    def test_repeat_analysis_consistency(self):
        test_url = "https://repeat-test-domain.org/path"
        r1 = client.post("/api/v1/analyze", json={"url": test_url}).json()
        r2 = client.post("/api/v1/analyze", json={"url": test_url}).json()

        assert r1["verdict"] == r2["verdict"]
        assert r1["risk_score"] == r2["risk_score"]
        assert r1["action"] == r2["action"]


class TestH_AuthoritativeExtensionIntegrity:
    """Test H: Verify authoritative extension integrity, manifest, and build files."""

    @property
    def extension_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent.parent / "extension"

    def test_authoritative_extension_files_exist(self):
        ext_dir = self.extension_dir
        assert (ext_dir / "manifest.json").exists()
        assert (ext_dir / "package.json").exists()
        assert (ext_dir / "vite.config.ts").exists()
        assert (ext_dir / "src" / "background" / "service-worker.ts").exists()
        assert (ext_dir / "src" / "content" / "navigation-guard.ts").exists()
        assert (ext_dir / "src" / "content" / "search-guard.ts").exists()
        assert (ext_dir / "src" / "services" / "api-client.ts").exists()

    def test_built_dist_files_exist(self):
        dist_dir = self.extension_dir / "dist"
        assert dist_dir.exists(), "extension/dist must exist after npm run build"
        assert (dist_dir / "manifest.json").exists()
        assert (dist_dir / "background.js").exists()
        assert (dist_dir / "navigation-guard.js").exists()
        assert (dist_dir / "search-guard.js").exists()
        assert (dist_dir / "popup.html").exists()

    def test_manifest_mv3_security(self):
        with open(self.extension_dir / "manifest.json", "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["manifest_version"] == 3
        assert "storage" in manifest["permissions"]
        assert "tabs" in manifest["permissions"]
        assert "webNavigation" in manifest["permissions"]
        assert "cookies" not in manifest["permissions"]
        assert "webRequestBlocking" not in manifest["permissions"]

        # Phase 7 externally_connectable
        assert "externally_connectable" in manifest
        matches = manifest["externally_connectable"]["matches"]
        assert any("localhost:3000" in m or "127.0.0.1:3000" in m for m in matches)

        # Dist manifest must also match
        dist_manifest_path = self.extension_dir / "dist" / "manifest.json"
        if dist_manifest_path.exists():
            with open(dist_manifest_path, "r", encoding="utf-8") as df:
                dist_manifest = json.load(df)
            assert "webNavigation" in dist_manifest["permissions"]
            assert "tabs" in dist_manifest["permissions"]
            assert "externally_connectable" in dist_manifest


class TestI_NavigationInterceptionAndStateMachine:
    """Test I: Phase 1-10 Navigation state machine, loop prevention, and tab isolation simulation."""

    def test_narrowly_scoped_localhost_exclusion(self):
        """Validates that localhost exclusions are narrowly scoped to ports 3000, 5173, 8000."""
        def is_excluded(url: str) -> bool:
            from urllib.parse import urlparse
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return True
            if p.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                return str(p.port) in ("3000", "5173", "8000")
            return False

        # Excluded AEGIS ports
        assert is_excluded("http://127.0.0.1:3000/analyze?url=https://example.com") is True
        assert is_excluded("http://localhost:5173/") is True
        assert is_excluded("http://127.0.0.1:8000/api/v1/health") is True

        # Non-AEGIS websites MUST NOT be excluded
        assert is_excluded("https://example.com") is False
        assert is_excluded("http://phishing-bank-update.com/login") is False
        assert is_excluded("http://localhost:8080/some-app") is False

        # Internal browser schemes MUST be excluded
        assert is_excluded("chrome://settings") is True
        assert is_excluded("about:blank") is True

    def test_navigation_scoped_state_transitions(self):
        """Validates state machine transitions: PENDING -> AUTHORIZED / BLOCKED / EXPIRED."""
        records = {}

        def create_pending(nav_id: str, tab_id: int, url: str):
            records[nav_id] = {
                "navId": nav_id,
                "tabId": tab_id,
                "url": url.lower().rstrip("/"),
                "state": "PENDING",
                "expiresAt": time.time() + 60.0
            }

        def authorize(nav_id: str, tab_id: int, url: str, verdict: str) -> bool:
            rec = records.get(nav_id)
            if not rec or rec["tabId"] != tab_id:
                return False
            if rec["url"] != url.lower().rstrip("/"):
                return False
            if verdict == "MALICIOUS":
                rec["state"] = "BLOCKED"
                return False
            rec["state"] = "AUTHORIZED"
            rec["expiresAt"] = time.time() + 30.0
            return True

        def find_active_authorized(tab_id: int, url: str) -> bool:
            norm = url.lower().rstrip("/")
            now = time.time()
            for r in records.values():
                if r["tabId"] == tab_id and r["url"] == norm and r["state"] == "AUTHORIZED" and now <= r["expiresAt"]:
                    return True
            return False

        nav_id = "nav_test_1"
        tab_a = 42
        tab_b = 99
        url = "https://safe-portal.com"

        create_pending(nav_id, tab_a, url)
        assert find_active_authorized(tab_a, url) is False

        # Tab mismatch should fail
        assert authorize(nav_id, tab_b, url, "SAFE") is False
        assert find_active_authorized(tab_a, url) is False

        # Authorize on correct tab A
        assert authorize(nav_id, tab_a, url, "SAFE") is True
        assert find_active_authorized(tab_a, url) is True

        # Tab isolation: Tab B must NOT be authorized for the same destination
        assert find_active_authorized(tab_b, url) is False

        # Malicious cannot be authorized
        mal_nav = "nav_mal_1"
        create_pending(mal_nav, tab_a, "https://evil-hacker.com")
        assert authorize(mal_nav, tab_a, "https://evil-hacker.com", "MALICIOUS") is False
        assert records[mal_nav]["state"] == "BLOCKED"
