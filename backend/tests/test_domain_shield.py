"""
Comprehensive Unit Tests for DomainShield (Phase 5)
Tests:
- Official brand domains & legitimate subdomains (False Positive controls)
- Character substitution, insertion, deletion, transposition (Damerau-Levenshtein)
- Homoglyphs, confusable Unicode characters, and Punycode
- Subdomain impersonation attacks
- Suspicious brand + security keyword domain composition
- Benign words containing brand sub-strings (False Positive controls)
- Multi-label public suffixes and malformed URLs
- Structured response contract validation
"""

import pytest
from app.services.domain_shield import (
    check_domain_impersonation,
    normalize_domain_string,
    decompose_hostname,
    detect_typosquatting_technique
)


class TestDomainShieldNormalization:
    """Test URL and hostname normalization, IDN decoding, and decomposition."""

    def test_normalize_standard_domain(self):
        norm_str, has_homoglyphs, techs = normalize_domain_string("google.com")
        assert norm_str == "google.com"
        assert has_homoglyphs is False

    def test_normalize_punycode(self):
        norm_str, has_homoglyphs, techs = normalize_domain_string("xn--pple-43d.com")
        assert "pple" in norm_str or "apple" in norm_str

    def test_decompose_standard_domain(self):
        sub, sld, suffix, reg = decompose_hostname("mail.google.com")
        assert reg == "google.com"
        assert sld == "google"
        assert sub == "mail"

    def test_decompose_multilabel_suffix(self):
        sub, sld, suffix, reg = decompose_hostname("secure.login.paypal.co.uk")
        assert reg == "paypal.co.uk"
        assert sld == "paypal"
        assert sub == "secure.login"

    def test_decompose_no_subdomain(self):
        sub, sld, suffix, reg = decompose_hostname("netflix.com")
        assert reg == "netflix.com"
        assert sld == "netflix"
        assert sub == ""


class TestDomainShieldOfficialDomains:
    """Verify that legitimate official brand domains and subdomains are NEVER flagged."""

    @pytest.mark.parametrize("url,brand", [
        ("https://google.com", "Google"),
        ("https://www.google.com", "Google"),
        ("https://accounts.google.com/signin", "Google"),
        ("https://mail.google.com", "Google"),
        ("https://apple.com", "Apple"),
        ("https://www.apple.com/shop", "Apple"),
        ("https://icloud.com", "Apple"),
        ("https://microsoft.com", "Microsoft"),
        ("https://login.microsoftonline.com", "Microsoft"),
        ("https://paypal.com", "PayPal"),
        ("https://www.paypal.com/signin", "PayPal"),
        ("https://paypal-community.com", "PayPal"),
        ("https://github.com", "GitHub"),
        ("https://api.github.com", "GitHub"),
        ("https://amazon.com", "Amazon"),
        ("https://aws.amazon.com", "Amazon"),
        ("https://openai.com", "OpenAI"),
        ("https://chatgpt.com", "OpenAI"),
        ("https://netflix.com", "Netflix"),
        ("https://chase.com", "Chase Bank"),
        ("https://wellsfargo.com", "Wells Fargo"),
        ("https://bankofamerica.com", "Bank of America"),
    ])
    def test_official_domains_are_clean(self, url, brand):
        result = check_domain_impersonation(url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is False
        assert result["matched_brand"] == brand
        assert result["confidence"] == 1.0
        assert "Official verified domain" in result["reasoning"]


class TestDomainShieldTyposquatting:
    """Test character mutations: substitution, insertion, deletion, transposition."""

    @pytest.mark.parametrize("url,expected_tech,brand", [
        ("https://g00gle.com", "character_substitution", "Google"),
        ("https://paypa1.com", "character_substitution", "PayPal"),
        ("https://micros0ft.com", "character_substitution", "Microsoft"),
        ("https://amaz0n.com", "character_substitution", "Amazon"),
        ("https://app1e.com", "character_substitution", "Apple"),
        ("https://gooogle.com", "character_insertion", "Google"),
        ("https://amazonn.com", "character_insertion", "Amazon"),
        ("https://netflixx.com", "character_insertion", "Netflix"),
        ("https://gogle.com", "character_deletion", "Google"),
        ("https://paypl.com", "character_deletion", "PayPal"),
        ("https://microsft.com", "character_deletion", "Microsoft"),
        ("https://googel.com", "character_transposition", "Google"),
        ("https://amzaon.com", "character_transposition", "Amazon"),
    ])
    def test_typosquatting_mutations(self, url, expected_tech, brand):
        result = check_domain_impersonation(url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == brand
        assert any(expected_tech in t for t in result["detection_techniques"])
        assert result["confidence"] >= 0.70
        assert result["similarity_score"] >= 75


class TestDomainShieldHomoglyphsAndIDN:
    """Test Unicode confusables and Punycode attacks."""

    def test_cyrillic_homoglyph_attack(self):
        # 'о' is Cyrillic small letter U+043E, visually identical to Latin 'o'
        cyrillic_url = "http://g\u043e\u043egle.com"
        result = check_domain_impersonation(cyrillic_url)
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == "Google"
        assert any("homoglyph" in t or "substitution" in t for t in result["detection_techniques"])
        assert result["confidence"] >= 0.85

    def test_apple_homoglyph(self):
        # 'а' is Cyrillic small letter U+0430
        cyrillic_apple = "http://\u0430pple.com"
        result = check_domain_impersonation(cyrillic_apple)
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == "Apple"

    def test_punycode_domain(self):
        # xn--pple-43d.com is Punycode for Cyrillic 'аpple.com'
        punycode_url = "http://xn--pple-43d.com"
        result = check_domain_impersonation(punycode_url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == "Apple"

    def test_invisible_zero_width_character_attack(self):
        # Zero-width space U+200B inserted into brand name
        zero_width_url = "http://g\u200boogle.com"
        result = check_domain_impersonation(zero_width_url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == "Google"
        assert any("invisible" in t for t in result["detection_techniques"])

    def test_bidirectional_override_attack(self):
        # Right-to-Left Override U+202E inserted into domain
        bidi_url = "http://\u202egoogle.com"
        result = check_domain_impersonation(bidi_url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == "Google"
        assert any("invisible" in t for t in result["detection_techniques"])


class TestDomainShieldSubdomainImpersonation:
    """Test brand placed in subdomain of an attacker-controlled registrable domain."""

    @pytest.mark.parametrize("url,brand", [
        ("https://google.com.attacker-example.com/login", "Google"),
        ("https://paypal.secure-login-portal.net", "PayPal"),
        ("https://netflix.account-billing.xyz", "Netflix"),
        ("https://chase.online-verify.info", "Chase Bank"),
        ("https://microsoft.com.malicious-site.org", "Microsoft"),
    ])
    def test_subdomain_impersonation(self, url, brand):
        result = check_domain_impersonation(url)
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == brand
        assert any("subdomain" in t for t in result["detection_techniques"])
        assert result["confidence"] >= 0.80


class TestDomainShieldBrandKeywordComposition:
    """Test brand names combined with deceptive security/auth keywords."""

    @pytest.mark.parametrize("url,brand", [
        ("https://google-security-verify.com", "Google"),
        ("https://paypal-account-update.com", "PayPal"),
        ("https://apple-id-support-login.com", "Apple"),
        ("https://microsoft-office-auth.com", "Microsoft"),
        ("https://chase-bank-security-center.com", "Chase Bank"),
    ])
    def test_brand_keyword_impersonation(self, url, brand):
        result = check_domain_impersonation(url)
        assert result["impersonation_detected"] is True
        assert result["matched_brand"] == brand
        assert any("keyword" in t or "composition" in t for t in result["detection_techniques"])
        assert result["confidence"] >= 0.80


class TestDomainShieldFalsePositiveControls:
    """Ensure benign domains containing brand substrings or coincidental words are NOT flagged."""

    @pytest.mark.parametrize("url", [
        ("https://pineapple.com"),
        ("https://anecdote.com"),
        ("https://metabolism.com"),
        ("https://appalachian.org"),
        ("https://goggles.org"),
        ("https://chase-the-dream.org"),
        ("https://example.com"),
        ("https://wikipedia.org"),
        ("https://python.org"),
        ("https://stackoverflow.com"),
        ("https://awe.com"),
        ("https://beta.com"),
        ("https://chase.cam.ac.uk"),
        ("https://münchen.de"),
    ])
    def test_benign_domains_not_flagged(self, url):
        result = check_domain_impersonation(url)
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is False


class TestDomainShieldEdgeCases:
    """Test malformed URLs, empty inputs, IP addresses, and contract integrity."""

    def test_empty_url(self):
        result = check_domain_impersonation("")
        assert result["status"] == "failed"
        assert result["impersonation_detected"] is False

    def test_ip_address(self):
        result = check_domain_impersonation("http://192.168.1.1/admin")
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is False

    def test_localhost(self):
        result = check_domain_impersonation("http://localhost:8000/docs")
        assert result["status"] == "completed"
        assert result["impersonation_detected"] is False

    def test_result_contract_fields(self):
        result = check_domain_impersonation("https://paypa1.com")
        expected_keys = [
            "status", "impersonation_detected", "matched_brand",
            "official_target_domain", "observed_hostname", "registrable_domain",
            "similarity_score", "detection_techniques", "supporting_evidence",
            "confidence", "reasoning", "limitations"
        ]
        for key in expected_keys:
            assert key in result, f"Missing key '{key}' in DomainShield contract"
