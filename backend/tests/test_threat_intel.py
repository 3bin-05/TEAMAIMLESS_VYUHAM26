import pytest
from pathlib import Path

from cyber_analysis.threat_intel import LocalThreatIntelProvider


def test_local_threat_intel_allowlist_match(tmp_path):
    """1 & 4. Test exact and subdomain allowlist matching."""
    allow_file = tmp_path / "allow.txt"
    block_file = tmp_path / "block.txt"

    allow_file.write_text("google.com\ngithub.com\n")
    block_file.write_text("malicious.example.test\n")

    provider = LocalThreatIntelProvider(allowlist_path=allow_file, blocklist_path=block_file)

    res1 = provider.lookup_domain("google.com")
    assert res1.available is True
    assert res1.data["is_allowlisted"] is True
    assert res1.data["is_blocked"] is False
    assert len(res1.signals) == 1
    assert res1.signals[0].type == "allowlisted_domain"

    # Subdomain match
    res2 = provider.lookup_domain("sub.github.com")
    assert res2.data["is_allowlisted"] is True


def test_local_threat_intel_blocklist_match(tmp_path):
    """1, 2, 10. Test exact and domain-boundary blocklist matching."""
    allow_file = tmp_path / "allow.txt"
    block_file = tmp_path / "block.txt"

    allow_file.write_text("")
    block_file.write_text("malicious.example.test\nphish.com\n")

    provider = LocalThreatIntelProvider(allowlist_path=allow_file, blocklist_path=block_file)

    res1 = provider.lookup_domain("malicious.example.test")
    assert res1.available is True
    assert res1.data["is_blocked"] is True
    assert len(res1.signals) == 1
    assert res1.signals[0].type == "known_malicious_match"
    assert res1.signals[0].severity == "critical"

    # Domain boundary check: notbadexample.com must NOT match badexample.com
    res2 = provider.lookup_domain("notmalicious.example.test")
    assert res2.data["is_blocked"] is False


def test_local_threat_intel_no_match(tmp_path):
    """3. Test lookup with no match in allowlist or blocklist."""
    allow_file = tmp_path / "allow.txt"
    block_file = tmp_path / "block.txt"
    allow_file.write_text("google.com\n")
    block_file.write_text("bad.com\n")

    provider = LocalThreatIntelProvider(allowlist_path=allow_file, blocklist_path=block_file)
    res = provider.lookup_domain("unknown-domain-1234.org")

    assert res.available is True
    assert res.data["matched"] is False
    assert len(res.signals) == 0


def test_local_threat_intel_lookup_url(tmp_path):
    """Test lookup_url method extracts hostname correctly."""
    allow_file = tmp_path / "allow.txt"
    block_file = tmp_path / "block.txt"
    block_file.write_text("badbank.com\n")

    provider = LocalThreatIntelProvider(allowlist_path=allow_file, blocklist_path=block_file)
    res = provider.lookup_url("http://badbank.com/login/credential.php?user=123")

    assert res.available is True
    assert res.data["is_blocked"] is True
    assert len(res.signals) == 1
    assert res.signals[0].type == "known_malicious_match"


def test_official_restricted_domains():
    """Test recognition and safe signal generation for non-publicly purchasable official TLDs."""
    provider = LocalThreatIntelProvider()

    test_cases = [
        ("irs.gov", "gov", "Government"),
        ("navy.mil", "mil", "Military"),
        ("who.int", "int", "International Organization"),
        ("harvard.edu", "edu", "Education"),
        ("argentina.gob", "gob", "Government"),
        ("met.police", "police", "Law Enforcement"),
        ("chase.bank", "bank", "Banking"),
        ("travelers.insurance", "insurance", "Insurance"),
        # ccTLD / multi-level official domains
        ("gov.uk", "gov.uk", "Government"),
        ("service.gov.in", "gov.in", "Government"),
        ("mit.edu.au", "edu.au", "Education"),
        ("ox.ac.uk", "ac.uk", "Education"),
        ("police.uk", "police.uk", "Law Enforcement"),
    ]

    for domain_or_url, expected_tld_part, expected_category in test_cases:
        res = provider.lookup_url(f"https://{domain_or_url}/verify-account-security")
        assert res.available is True
        assert res.data["is_official_domain"] is True
        assert res.data["official_info"] is not None
        assert expected_category in res.data["official_info"]["category"]
        assert any(sig.type == "official_restricted_domain" for sig in res.signals)

