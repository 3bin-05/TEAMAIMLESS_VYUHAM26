"""
Unit & Integration Tests for SearchGuard (Phase 5)
Verifies:
- Chrome Manifest V3 configuration & least-privilege security permissions
- Google redirect decoding and destination URL normalization logic
- Destination exclusion criteria (internal Google domains, non-http schemes)
- Batch endpoint capacity and constraints (max 20 URLs)
"""

import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestSearchGuardManifestAndSecurity:
    """Validate Extension Manifest V3 security requirements for authoritative AEGIS extension."""

    @property
    def extension_dir(self) -> Path:
        # Authoritative extension located at Aegis/extension
        return Path(__file__).resolve().parent.parent.parent / "extension"

    def test_manifest_exists_and_is_valid_mv3(self):
        manifest_path = self.extension_dir / "manifest.json"
        assert manifest_path.exists(), f"Authoritative extension/manifest.json does not exist at {manifest_path}"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest.get("manifest_version") == 3
        assert "AEGIS" in manifest.get("name")
        assert "background" in manifest
        assert manifest["background"].get("service_worker") == "background.js"

    def test_least_privilege_permissions(self):
        """Verify no invasive permissions like cookies or webRequestBlocking."""
        manifest_path = self.extension_dir / "manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        perms = manifest.get("permissions", [])
        assert "cookies" not in perms
        assert "webRequestBlocking" not in perms
        assert "history" not in perms

    def test_extension_files_present(self):
        ext_dir = self.extension_dir
        expected_files = [
            "manifest.json",
            "package.json",
            "vite.config.ts",
            "src/background/service-worker.ts",
            "src/content/navigation-guard.ts",
            "src/content/search-guard.ts",
            "src/services/api-client.ts"
        ]
        for fname in expected_files:
            p = ext_dir / fname
            assert p.exists(), f"Expected authoritative extension file missing: {fname}"


class TestSearchGuardUrlExtractionLogic:
    """Simulate SearchGuard URL extraction & redirect unwrapping logic."""

    @staticmethod
    def extract_searchguard_url(raw_href: str) -> str | None:
        """Python mirror of content_searchguard.js extractDestinationUrl."""
        if not raw_href:
            return None

        # Check for Google redirect wrapper
        if "/url?" in raw_href:
            parsed = urlparse(raw_href)
            qs = parse_qs(parsed.query)
            target = qs.get("q", [None])[0] or qs.get("url", [None])[0]
            if target:
                raw_href = target

        parsed_dest = urlparse(raw_href)
        if parsed_dest.scheme not in ("http", "https"):
            return None

        hostname = (parsed_dest.hostname or "").lower()
        # Internal google domains
        google_domains = [
            "google.com", "www.google.com", "accounts.google.com",
            "support.google.com", "maps.google.com", "policies.google.com"
        ]
        if hostname in google_domains or hostname.endswith(".google.com"):
            return None

        return raw_href

    def test_extract_direct_url(self):
        url = "https://www.wikipedia.org/wiki/Phishing"
        assert self.extract_searchguard_url(url) == url

    def test_extract_google_redirect_wrapper(self):
        redirect = "https://www.google.com/url?q=https://example.com/target&sa=U&ved=2ahUKEwi"
        extracted = self.extract_searchguard_url(redirect)
        assert extracted == "https://example.com/target"

    def test_filter_out_internal_google_domains(self):
        assert self.extract_searchguard_url("https://accounts.google.com/signin") is None
        assert self.extract_searchguard_url("https://maps.google.com") is None
        assert self.extract_searchguard_url("https://support.google.com/websearch") is None

    def test_filter_out_javascript_and_invalid_schemes(self):
        assert self.extract_searchguard_url("javascript:void(0)") is None
        assert self.extract_searchguard_url("mailto:test@example.com") is None
        assert self.extract_searchguard_url("") is None


class TestSearchGuardBatchApiConstraints:
    """Test batch API limits enforced for SearchGuard."""

    def test_batch_api_under_limit(self, client):
        urls = [f"https://example{i}.org" for i in range(5)]
        resp = client.post("/api/v1/analyze/batch", json={"urls": urls})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 5

    def test_batch_api_rejects_exceeding_20_urls(self, client):
        urls = [f"https://example{i}.org" for i in range(25)]
        resp = client.post("/api/v1/analyze/batch", json={"urls": urls})
        # Batch max limit is 20
        assert resp.status_code == 422 or resp.status_code == 400
