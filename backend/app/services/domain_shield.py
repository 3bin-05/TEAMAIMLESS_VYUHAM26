"""
AEGIS DomainShield — Advanced Typosquatting and Domain Impersonation Detection Engine.
Implements multi-technique domain analysis:
1. URL parsing & hostname extraction
2. IDNA normalization & Punycode decoding
3. Unicode normalization & Confusable/Homoglyph mapping
4. Public Suffix List decomposition (registrable domain vs subdomains)
5. Official brand domain whitelist verification (false-positive controls)
6. Subdomain brand injection & boundary impersonation
7. Damerau-Levenshtein typosquatting (substitution, insertion, deletion, transposition)
8. Brand + security/authentication keyword composition
9. Evidence synthesis, confidence rating, and structured reporting
"""

import logging
from typing import Any, Tuple, List, Optional
import re
import unicodedata
from urllib.parse import urlparse
import idna
from rapidfuzz.distance import DamerauLevenshtein
from rapidfuzz.fuzz import ratio
import tldextract

from app.services.brand_database import (
    BRAND_CATALOG,
    BENIGN_SUBSTRING_WORDS,
    CONFUSABLE_MAP,
    SUSPICIOUS_SECURITY_KEYWORDS,
)

logger = logging.getLogger("aegis")


def extract_url_host(url: str) -> str:
    """Extracts lowercase hostname safely from URL string without network calls."""
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url
    parsed = urlparse(clean_url)
    host = parsed.hostname or ""
    return host.lower().strip()


# Invisible / zero-width characters and bidirectional override control characters
INVISIBLE_OR_BIDI_CHARS = {
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad",  # Zero-width spaces, joiners, soft hyphen, BOM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE, RLE, PDF, LRO, RLO
    "\u2066", "\u2067", "\u2068", "\u2069"              # LRI, RLI, FSI, PDI
}


def normalize_domain_string(raw_str: str) -> tuple[str, bool, list[str]]:
    """
    Normalizes domain string using:
    - IDNA Punycode decoding (`xn--...`)
    - Invisible and bidirectional character stripping
    - Unicode NFKC canonical decomposition
    - Homoglyph & confusable character substitution
    Returns (normalized_string, has_homoglyphs, techniques_triggered).
    """
    techniques = []
    has_homoglyphs = False
    s = raw_str

    # 1. Invisible and bidirectional override detection & stripping
    if any(ch in INVISIBLE_OR_BIDI_CHARS for ch in s):
        has_homoglyphs = True
        techniques.append("invisible_character_attack")
        s = "".join(ch for ch in s if ch not in INVISIBLE_OR_BIDI_CHARS)

    # 2. Punycode decoding
    if "xn--" in s:
        try:
            decoded = idna.decode(s)
            techniques.append("punycode_decoding")
            s = decoded
        except Exception:
            pass

    # 3. Unicode NFKC normalization
    s = unicodedata.normalize("NFKC", s)

    # 4. Confusable mapping
    normalized_chars = []
    found_confusables = False
    for ch in s:
        if ch in CONFUSABLE_MAP:
            normalized_chars.append(CONFUSABLE_MAP[ch])
            found_confusables = True
        else:
            normalized_chars.append(ch)

    normalized_str = "".join(normalized_chars)
    if found_confusables:
        has_homoglyphs = True
        techniques.append("homoglyph_substitution")

    return normalized_str, has_homoglyphs, techniques


def decompose_hostname(hostname: str) -> tuple[str, str, str, str]:
    """
    Decomposes hostname into (subdomain, domain_label, suffix, registrable_domain)
    using the Public Suffix List via tldextract.
    """
    ext = tldextract.extract(hostname)
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    domain_label = ext.domain.lower() if ext.domain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    registrable_domain = f"{domain_label}.{suffix}" if domain_label and suffix else hostname
    return subdomain, domain_label, suffix, registrable_domain


def detect_typosquatting_technique(target: str, candidate: str) -> tuple[str | None, int]:
    """
    Determines specific typosquatting technique and Damerau-Levenshtein distance
    between a target brand name and candidate domain label.
    """
    dist = DamerauLevenshtein.distance(target, candidate)
    if dist > 2:
        return None, dist

    len_diff = len(candidate) - len(target)

    # Single or double character insertion
    if len_diff > 0 and dist == len_diff:
        return "character_insertion", dist

    # Single or double character deletion
    if len_diff < 0 and dist == abs(len_diff):
        return "character_deletion", dist

    # Same length: transposition or substitution
    if len_diff == 0:
        # Check if adjacent swap
        transposition_found = False
        for i in range(len(target) - 1):
            swapped = list(target)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            if "".join(swapped) == candidate:
                transposition_found = True
                break
        if transposition_found:
            return "character_transposition", dist
        if dist == 1 or dist == 2:
            return "character_substitution", dist

    return "edit_distance_variant", dist


def check_domain_impersonation(url: str) -> dict[str, Any]:
    """
    Executes comprehensive multi-layer DomainShield analysis.
    Identifies brand impersonation, typosquatting, homoglyphs, and deceptive subdomains.
    Returns typed, explainable result dictionary.
    """
    hostname = extract_url_host(url)
    if not hostname:
        return {
            "status": "failed",
            "impersonation_detected": False,
            "matched_brand": None,
            "official_target_domain": None,
            "official_domain": None,
            "observed_hostname": "",
            "registrable_domain": "",
            "similarity_score": 0.0,
            "detection_techniques": [],
            "techniques_triggered": [],
            "supporting_evidence": [],
            "evidence": [],
            "confidence": 0.0,
            "reasoning": "URL has no valid hostname.",
            "reason": "URL has no valid hostname.",
            "limitations": "Invalid or missing hostname in input URL."
        }

    subdomain, domain_label, suffix, registrable_domain = decompose_hostname(hostname)

    # --------------------------------------------------------------------------
    # LAYER 1: OFFICIAL DOMAIN WHITELIST VERIFICATION (False-Positive Control)
    # --------------------------------------------------------------------------
    # If the registrable domain is in the brand's verified official domains,
    # it is the genuine entity and CANNOT be an impersonation.
    for brand_key, brand_info in BRAND_CATALOG.items():
        if registrable_domain in brand_info["official_domains"]:
            return {
                "status": "completed",
                "impersonation_detected": False,
                "matched_brand": brand_info["name"],
                "official_target_domain": registrable_domain,
                "official_domain": registrable_domain,
                "observed_hostname": hostname,
                "registrable_domain": registrable_domain,
                "similarity_score": 100.0,
                "detection_techniques": [],
                "techniques_triggered": [],
                "supporting_evidence": [f"Domain '{registrable_domain}' is a verified official domain of {brand_info['name']}."],
                "evidence": [f"Domain '{registrable_domain}' is a verified official domain of {brand_info['name']}."],
                "confidence": 1.0,
                "reasoning": f"Official verified domain belonging to {brand_info['name']}.",
                "reason": f"Official verified domain belonging to {brand_info['name']}.",
                "limitations": None
            }

    # --------------------------------------------------------------------------
    # LAYER 2: IDN & HOMOGLYPH NORMALIZATION
    # --------------------------------------------------------------------------
    norm_hostname, has_homoglyphs, homoglyph_techs = normalize_domain_string(hostname)
    _, norm_domain_label, _, norm_registrable = decompose_hostname(norm_hostname)

    best_match: dict[str, Any] | None = None
    highest_confidence = 0.0

    # --------------------------------------------------------------------------
    # LAYER 3: EVALUATE CANDIDATE AGAINST EACH PROTECTED BRAND
    # --------------------------------------------------------------------------
    for brand_key, brand_info in BRAND_CATALOG.items():
        brand_name = brand_info["name"]
        canonical_brand = brand_info["canonical_key"]
        aliases = brand_info["aliases"]
        min_sim = brand_info["min_similarity"]
        official_domains = brand_info["official_domains"]
        primary_official = next(iter(official_domains))

        candidate_labels = [domain_label]
        if norm_domain_label and norm_domain_label != domain_label:
            candidate_labels.append(norm_domain_label)

        for alias in aliases:
            # Check benign dictionary exclusion (e.g. pineapple contains apple)
            if domain_label in BENIGN_SUBSTRING_WORDS or norm_domain_label in BENIGN_SUBSTRING_WORDS:
                continue

            techniques_triggered = []
            evidence_points = []
            confidence = 0.0
            similarity = 0.0

            # ------------------------------------------------------------------
            # TECHNIQUE A: Homoglyph / Punycode Deceptive Exact Match
            # ------------------------------------------------------------------
            if has_homoglyphs:
                # If normalized domain label matches alias exactly, it's a homoglyph spoof
                if norm_domain_label == alias and domain_label != alias:
                    techniques_triggered.extend(homoglyph_techs)
                    techniques_triggered.append("homoglyph_attack")
                    similarity = 98.0
                    confidence = 0.95
                    evidence_points.append(
                        f"Domain uses confusable/homoglyph characters that resolve to protected brand '{brand_name}'."
                    )

            # ------------------------------------------------------------------
            # TECHNIQUE B: Subdomain Brand Injection / Mimicry
            # ------------------------------------------------------------------
            # Checks if subdomain mimics official brand domain (e.g., google.com.attacker.com)
            # or injects brand name (e.g., paypal.secure-update.com)
            subdomain_tokens = re.split(r"[\.\-_]", subdomain)
            if subdomain:
                # Subdomain contains exact official domain (e.g. "paypal.com" in "paypal.com.evil.com")
                for off_dom in official_domains:
                    if off_dom in subdomain or subdomain.endswith(off_dom):
                        techniques_triggered.append("subdomain_brand_impersonation")
                        evidence_points.append(
                            f"Subdomain contains full official brand domain '{off_dom}' under unrelated registry."
                        )
                        similarity = max(similarity, 95.0)
                        confidence = max(confidence, 0.92)
                        break

                # Subdomain contains exact brand alias
                if alias in subdomain_tokens and "subdomain_brand_impersonation" not in techniques_triggered:
                    # Common dictionary words (e.g. chase, apple, meta) as subdomains require suspicious security keywords
                    # or containing full official domain to avoid false positives on sites like chase.cam.ac.uk
                    is_dictionary_word = alias in {"chase", "apple", "meta"}
                    all_tokens = set(re.split(r"[\.\-_]", hostname))
                    has_security_keyword = any(kw in all_tokens for kw in SUSPICIOUS_SECURITY_KEYWORDS)
                    if not is_dictionary_word or has_security_keyword:
                        techniques_triggered.append("subdomain_brand_injection")
                        evidence_points.append(
                            f"Subdomain injects protected brand name '{brand_name}'."
                        )
                        similarity = max(similarity, 90.0)
                        confidence = max(confidence, 0.88)

            # ------------------------------------------------------------------
            # TECHNIQUE C: Brand + Security Keyword Hyphenation / Composition
            # ------------------------------------------------------------------
            # Checks for combinations like "google-security-verify", "paypal-account-update"
            for cand in candidate_labels:
                tokens = re.split(r"[\-_]", cand)
                if alias in tokens and len(tokens) > 1:
                    found_keywords = [kw for kw in tokens if kw in SUSPICIOUS_SECURITY_KEYWORDS]
                    if found_keywords:
                        techniques_triggered.append("brand_security_keyword_composition")
                        evidence_points.append(
                            f"Domain combines brand '{brand_name}' with deceptive security keywords: {', '.join(found_keywords)}."
                        )
                        similarity = max(similarity, 92.0)
                        confidence = max(confidence, 0.90)
                    else:
                        # Common dictionary words (e.g. chase, apple, meta) in benign phrases are NOT impersonations
                        if alias not in {"chase", "apple", "meta"}:
                            techniques_triggered.append("brand_embedded_in_domain")
                            evidence_points.append(
                                f"Domain embeds protected brand '{brand_name}' with extraneous keywords."
                            )
                            similarity = max(similarity, 85.0)
                            confidence = max(confidence, 0.80)

            # ------------------------------------------------------------------
            # TECHNIQUE D: Damerau-Levenshtein Typosquatting Analysis
            # ------------------------------------------------------------------
            for cand in candidate_labels:
                if not cand or cand == alias:
                    continue

                # Short brand aliases (< 4 characters like "aws") have high collision rates with legitimate short words
                if len(alias) < 4:
                    continue

                # Exclude if candidate is a benign dictionary word
                if cand in BENIGN_SUBSTRING_WORDS:
                    continue

                typo_tech, dist = detect_typosquatting_technique(alias, cand)
                sim_ratio = ratio(alias, cand)

                # For 4-character aliases (e.g. "meta"), a 1-character difference is 25% change (e.g. "beta"),
                # so enforce the brand's minimum similarity threshold.
                # For longer brands (e.g. "apple", "google", "paypal"), standard 1-2 edit distance applies.
                is_typo = False
                if len(alias) == 4:
                    if dist <= 2 and sim_ratio >= min_sim:
                        is_typo = True
                else:
                    if dist <= 2 or sim_ratio >= min_sim:
                        is_typo = True

                if is_typo:
                    if typo_tech and typo_tech not in techniques_triggered:
                        techniques_triggered.append(f"typosquatting_{typo_tech}")

                    similarity = max(similarity, float(sim_ratio))
                    confidence = max(confidence, 0.85 if dist == 1 else 0.75)
                    evidence_points.append(
                        f"Domain label '{cand}' is a visual/edit-distance typo of '{alias}' "
                        f"(distance: {dist}, similarity: {sim_ratio:.1f}%)."
                    )

            # ------------------------------------------------------------------
            # Evaluate Best Brand Candidate
            # ------------------------------------------------------------------
            if techniques_triggered and confidence > highest_confidence:
                highest_confidence = confidence
                best_match = {
                    "matched_brand": brand_name,
                    "official_domain": primary_official,
                    "similarity_score": round(similarity, 1),
                    "techniques_triggered": list(dict.fromkeys(techniques_triggered)),
                    "evidence": list(dict.fromkeys(evidence_points)),
                    "confidence": round(confidence, 2)
                }

    # --------------------------------------------------------------------------
    # FINAL RESULT ASSEMBLY
    # --------------------------------------------------------------------------
    if best_match and highest_confidence >= 0.70:
        tech_list = best_match["techniques_triggered"]
        brand_target = best_match["matched_brand"]
        reason_msg = (
            f"DomainShield detected brand impersonation targeting {brand_target} "
            f"via {', '.join(tech_list)}."
        )
        return {
            "status": "completed",
            "impersonation_detected": True,
            "matched_brand": brand_target,
            "official_target_domain": best_match["official_domain"],
            "official_domain": best_match["official_domain"],
            "observed_hostname": hostname,
            "registrable_domain": registrable_domain,
            "similarity_score": best_match["similarity_score"],
            "detection_techniques": tech_list,
            "techniques_triggered": tech_list,
            "supporting_evidence": best_match["evidence"],
            "evidence": best_match["evidence"],
            "confidence": best_match["confidence"],
            "reasoning": reason_msg,
            "reason": reason_msg,
            "limitations": None
        }

    # Clean / No Impersonation Detected
    return {
        "status": "completed",
        "impersonation_detected": False,
        "matched_brand": None,
        "official_target_domain": None,
        "official_domain": None,
        "observed_hostname": hostname,
        "registrable_domain": registrable_domain,
        "similarity_score": 0.0,
        "detection_techniques": [],
        "techniques_triggered": [],
        "supporting_evidence": ["No brand impersonation, typosquatting, or deceptive homoglyphs detected."],
        "evidence": ["No brand impersonation, typosquatting, or deceptive homoglyphs detected."],
        "confidence": 0.90,
        "reasoning": "Domain does not exhibit brand impersonation characteristics.",
        "reason": "Domain does not exhibit brand impersonation characteristics.",
        "limitations": None
    }