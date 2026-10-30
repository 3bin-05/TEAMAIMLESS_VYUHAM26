import re
from typing import Optional, Dict, Any, List


KNOWN_BRANDS = [
    {
        "name": "Facebook",
        "official_domain": "facebook.com",
        "keywords": ["facebook", "facelook", "faceb00k", "facebk", "faebook", "fecebook", "faceboook", "facebook-login", "facebook-security"],
        "stem": "facebook",
    },
    {
        "name": "Google",
        "official_domain": "google.com",
        "keywords": ["google", "g00gle", "gogle", "googl", "googel", "google-login", "google-verify"],
        "stem": "google",
    },
    {
        "name": "PayPal",
        "official_domain": "paypal.com",
        "keywords": ["paypal", "paypa1", "paypai", "paypal-security", "paypa1-verify", "paypa1-login"],
        "stem": "paypal",
    },
    {
        "name": "Microsoft",
        "official_domain": "microsoft.com",
        "keywords": ["microsoft", "microsooft", "microsft", "msn-login", "microsoft-online", "office365-login"],
        "stem": "microsoft",
    },
    {
        "name": "Apple",
        "official_domain": "apple.com",
        "keywords": ["apple", "app1e", "apple-id-verify", "aple", "icloud-login"],
        "stem": "apple",
    },
    {
        "name": "Amazon",
        "official_domain": "amazon.com",
        "keywords": ["amazon", "amaz0n", "amzon", "amazon-verify"],
        "stem": "amazon",
    },
    {
        "name": "Netflix",
        "official_domain": "netflix.com",
        "keywords": ["netflix", "netfl1x", "netflx", "netflix-billing"],
        "stem": "netflix",
    },
    {
        "name": "OpenAI / ChatGPT",
        "official_domain": "chatgpt.com",
        "keywords": ["chatgpt", "opena1", "open-ai", "chat-gpt", "chatgpt-login"],
        "stem": "chatgpt",
    },
    {
        "name": "Instagram",
        "official_domain": "instagram.com",
        "keywords": ["instagram", "instagr4m", "instgrm", "instagram-help"],
        "stem": "instagram",
    },
    {
        "name": "Chase Bank",
        "official_domain": "chase.com",
        "keywords": ["chase-security", "chase-login", "chase-verify", "chaseonline"],
        "stem": "chase",
    },
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_brand_lookalike(hostname: str) -> Optional[Dict[str, Any]]:
    """Detect if a hostname is an impersonation, typosquat, or lookalike of a known brand.

    Args:
        hostname: Normalized domain or hostname string.

    Returns:
        Dict with detection details if lookalike detected, else None.
    """
    if not hostname:
        return None

    clean_host = hostname.lower().strip(".")
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    parts = clean_host.split(".")
    sld = parts[0] if parts else clean_host

    # Exact official domain match or authentic subdomain is NOT an impersonation
    for brand in KNOWN_BRANDS:
        official = brand["official_domain"]
        if clean_host == official or clean_host.endswith("." + official):
            return None

    # Check keyword and typosquatting signatures
    for brand in KNOWN_BRANDS:
        stem = brand["stem"]
        official = brand["official_domain"]

        # 1. Combosquatting / brand stem match in non-official domain (e.g. facelook.com, chase-security-login.com)
        matched_kw = next((kw for kw in brand["keywords"] if kw != stem and kw in clean_host), None)
        if matched_kw:
            return {
                "detected": True,
                "mimicked_brand": brand["name"],
                "official_domain": official,
                "suspicious_host": clean_host,
                "technique": "Typosquatting / Character Substitution" if len(matched_kw) == len(stem) else "Combosquatting / Brand Spoofing",
                "matched_pattern": matched_kw,
                "reason": f"Domain '{clean_host}' is a deceptive lookalike mimicking {brand['name']} ({official}).",
            }

        # 2. Levenshtein edit distance check on SLD (e.g. facelook vs facebook, g00gle vs google)
        dist = levenshtein_distance(sld, stem)
        if sld != stem and 0 < dist <= 2 and abs(len(sld) - len(stem)) <= 2:
            return {
                "detected": True,
                "mimicked_brand": brand["name"],
                "official_domain": official,
                "suspicious_host": clean_host,
                "technique": "Fuzzy Edit Distance / Typosquatting",
                "matched_pattern": sld,
                "reason": f"Domain '{clean_host}' is a close typosquat replica (edit distance {dist}) of official {brand['name']} ({official}).",
            }

    return None
