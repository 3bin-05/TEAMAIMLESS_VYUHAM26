from typing import Any
from urllib.parse import urlsplit


def extract_technical_anomalies(url: str, raw_features: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """
    Translates raw lexical and structural features into human-comprehensible technical anomaly signals.
    These signals provide supporting evidence to the Ollama LLM rather than overriding its decision.
    """
    anomalies: list[dict[str, Any]] = []
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()

    if raw_features is None:
        raw_features = {}

    url_length = raw_features.get("URLLength", len(url))
    no_of_subdomains = raw_features.get("NoOfSubDomain", max(0, hostname.count(".") - 1))
    no_of_obfuscated = raw_features.get("NoOfObfuscatedChar", url.count("-"))
    is_domain_ip = raw_features.get("IsDomainIP", 0)
    no_of_digits = raw_features.get("NoOfDigits", sum(1 for c in url if c.isdigit()))

    # 1. IP address as host
    if is_domain_ip == 1 or hostname.replace(".", "").isdigit():
        anomalies.append({
            "name": "Raw IP Address Host",
            "observed_value": hostname,
            "expected_value": "Standard domain name",
            "severity": "high",
            "explanation": "This website uses a raw numerical IP address instead of a standard domain name, a technique frequently used to bypass domain reputation controls."
        })

    # 2. Excessive Subdomain Depth
    if no_of_subdomains >= 3:
        anomalies.append({
            "name": "Abnormal Subdomain Depth",
            "observed_value": f"{no_of_subdomains} subdomains",
            "expected_value": "0 to 1 subdomains",
            "severity": "medium",
            "explanation": "This website uses an unusually deep subdomain hierarchy, which can be employed to disguise the actual destination server."
        })

    # 3. Excessive Hyphens / Obfuscation
    if no_of_obfuscated >= 3 or hostname.count("-") >= 2:
        anomalies.append({
            "name": "Multiple Hyphen Separators",
            "observed_value": f"{no_of_obfuscated} hyphens",
            "expected_value": "0 to 1 hyphens in domain",
            "severity": "medium",
            "explanation": "Multiple hyphens are present in the domain or path, commonly seen in typosquatting and impersonation attacks."
        })

    # 4. Abnormal URL Length
    if url_length > 85:
        anomalies.append({
            "name": "Elevated URL Length",
            "observed_value": f"{url_length} characters",
            "expected_value": "Under 60 characters for standard navigation",
            "severity": "low" if url_length < 130 else "medium",
            "explanation": "The URL is unusually long, which can indicate embedded tracking tokens, secondary redirection payloads, or obfuscation."
        })

    # 5. Excessive Numerical Characters
    if no_of_digits >= 8:
        anomalies.append({
            "name": "High Digit Concentration",
            "observed_value": f"{no_of_digits} numerical characters",
            "expected_value": "Few or zero numbers in primary domain",
            "severity": "low",
            "explanation": "The address contains a high concentration of numbers, frequently found in auto-generated phishing infrastructure."
        })

    # 6. Unencrypted Protocol
    if parsed.scheme.lower() == "http":
        anomalies.append({
            "name": "Unencrypted HTTP Scheme",
            "observed_value": "http://",
            "expected_value": "https:// (TLS encrypted)",
            "severity": "medium",
            "explanation": "The website does not enforce HTTPS encryption, exposing user communication and credentials to interception."
        })

    return anomalies
