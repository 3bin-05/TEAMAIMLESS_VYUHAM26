import ipaddress
from urllib.parse import urlsplit
from typing import Any


FEATURE_NAMES = [
    "IsHTTPS",
    "IsDomainIP",
    "URLLength",
    "NoOfSubDomain",
    "NoOfDots",
    "NoOfObfuscatedChar",
    "NoOfEqual",
    "NoOfQmark",
    "NoOfAmp",
    "NoOfDigits",
    "TLD_freq"
]


class URLFeatureExtractor:
    """
    Extracts reproducible, URL-only features aligned with PhishOFE dataset definitions.
    Does not require live webpage fetching or JavaScript execution.
    """

    def __init__(self, tld_frequencies: dict[str, float] | None = None):
        self.tld_frequencies = tld_frequencies or {}

    def extract_features(self, url: str) -> dict[str, Any]:
        """
        Extracts raw feature dictionary for a single URL.
        """
        raw_url = str(url).strip()
        parsed = urlsplit(raw_url)
        hostname = (parsed.hostname or "").lower()

        # IsHTTPS: 1 if scheme is https
        is_https = 1 if parsed.scheme.lower() == "https" else 0

        # IsDomainIP: 1 if hostname is IPv4 or IPv6 address
        is_ip = 0
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = 1
            except ValueError:
                is_ip = 0

        # TLD extraction and frequency
        tld = ""
        if "." in hostname and not is_ip:
            tld = hostname.split(".")[-1]
        tld_freq = self.tld_frequencies.get(tld, 0.0)

        # URL structural features
        url_length = len(raw_url)
        eff_host = hostname[4:] if hostname.startswith("www.") else hostname
        no_of_subdomain = max(0, eff_host.count(".") - 1) if not is_ip else 0
        no_of_dots = raw_url.count(".")
        no_of_obfuscated_char = raw_url.count("-")
        no_of_equal = raw_url.count("=")
        no_of_qmark = raw_url.count("?")
        no_of_amp = raw_url.count("&")
        no_of_digits = sum(1 for c in raw_url if c.isdigit())

        return {
            "IsHTTPS": is_https,
            "IsDomainIP": is_ip,
            "URLLength": url_length,
            "NoOfSubDomain": no_of_subdomain,
            "NoOfDots": no_of_dots,
            "NoOfObfuscatedChar": no_of_obfuscated_char,
            "NoOfEqual": no_of_equal,
            "NoOfQmark": no_of_qmark,
            "NoOfAmp": no_of_amp,
            "NoOfDigits": no_of_digits,
            "TLD_freq": tld_freq
        }

    def extract_vector(self, url: str) -> list[float]:
        """
        Extracts feature list strictly matching FEATURE_NAMES order.
        """
        feat_dict = self.extract_features(url)
        return [float(feat_dict[name]) for name in FEATURE_NAMES]
