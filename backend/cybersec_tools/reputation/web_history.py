import time
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity

# Catalog of major internet entities with deep historical web footprint & known WHOIS privacy patterns
MAJOR_WEB_ENTITIES: Dict[str, Dict[str, Any]] = {
    "instagram.com": {
        "entity": "Instagram / Meta Platforms Inc.",
        "category": "Social Media Platform",
        "authority": "HIGH",
        "established_year": 2010,
        "privacy_protected_standard": True,
        "description": "Global photo and video sharing social network owned by Meta Platforms.",
    },
    "facebook.com": {
        "entity": "Facebook / Meta Platforms Inc.",
        "category": "Social Media Platform",
        "authority": "HIGH",
        "established_year": 2004,
        "privacy_protected_standard": True,
        "description": "Primary social media platform of Meta Platforms Inc.",
    },
    "meta.com": {
        "entity": "Meta Platforms Inc.",
        "category": "Technology Conglomerate",
        "authority": "HIGH",
        "established_year": 2021,
        "privacy_protected_standard": True,
        "description": "Parent company of Instagram, Facebook, and WhatsApp.",
    },
    "whatsapp.com": {
        "entity": "WhatsApp / Meta Platforms Inc.",
        "category": "Messaging Platform",
        "authority": "HIGH",
        "established_year": 2009,
        "privacy_protected_standard": True,
        "description": "Encrypted messaging service owned by Meta.",
    },
    "google.com": {
        "entity": "Google LLC / Alphabet Inc.",
        "category": "Search & Cloud Platform",
        "authority": "HIGH",
        "established_year": 1997,
        "privacy_protected_standard": True,
        "description": "Global search engine, cloud, and productivity infrastructure.",
    },
    "youtube.com": {
        "entity": "YouTube / Google LLC",
        "category": "Video Streaming",
        "authority": "HIGH",
        "established_year": 2005,
        "privacy_protected_standard": True,
        "description": "World's largest video streaming platform.",
    },
    "apple.com": {
        "entity": "Apple Inc.",
        "category": "Consumer Technology & Services",
        "authority": "HIGH",
        "established_year": 1976,
        "privacy_protected_standard": True,
        "description": "Official technology manufacturer and services provider.",
    },
    "microsoft.com": {
        "entity": "Microsoft Corporation",
        "category": "Operating Systems & Cloud",
        "authority": "HIGH",
        "established_year": 1975,
        "privacy_protected_standard": True,
        "description": "Global enterprise software, Azure, and Windows platform.",
    },
    "amazon.com": {
        "entity": "Amazon.com Inc.",
        "category": "E-Commerce & Cloud Infrastructure",
        "authority": "HIGH",
        "established_year": 1994,
        "privacy_protected_standard": True,
        "description": "Global retail marketplace and AWS cloud provider.",
    },
    "openai.com": {
        "entity": "OpenAI OpCo LLC",
        "category": "Artificial Intelligence Research",
        "authority": "HIGH",
        "established_year": 2015,
        "privacy_protected_standard": True,
        "description": "Official website of ChatGPT and OpenAI models.",
    },
    "netflix.com": {
        "entity": "Netflix Inc.",
        "category": "Entertainment & Streaming",
        "authority": "HIGH",
        "established_year": 1997,
        "privacy_protected_standard": True,
        "description": "Global subscription video-on-demand platform.",
    },
    "github.com": {
        "entity": "GitHub / Microsoft",
        "category": "Developer Platform",
        "authority": "HIGH",
        "established_year": 2008,
        "privacy_protected_standard": True,
        "description": "World's primary open source and software repository platform.",
    },
    "chase.com": {
        "entity": "JPMorgan Chase & Co.",
        "category": "Financial Institution",
        "authority": "HIGH",
        "established_year": 2000,
        "privacy_protected_standard": True,
        "description": "Major United States commercial and investment bank.",
    },
    "paypal.com": {
        "entity": "PayPal Holdings Inc.",
        "category": "Payment Processor",
        "authority": "HIGH",
        "established_year": 1998,
        "privacy_protected_standard": True,
        "description": "Worldwide online payments system.",
    },
    "linkedin.com": {
        "entity": "LinkedIn Corporation / Microsoft",
        "category": "Professional Networking",
        "authority": "HIGH",
        "established_year": 2002,
        "privacy_protected_standard": True,
        "description": "Business and employment-focused social media platform.",
    },
    "twitter.com": {
        "entity": "X Corp. (formerly Twitter)",
        "category": "Social Media",
        "authority": "HIGH",
        "established_year": 2006,
        "privacy_protected_standard": True,
        "description": "Microblogging and social networking service.",
    },
    "x.com": {
        "entity": "X Corp.",
        "category": "Social Media",
        "authority": "HIGH",
        "established_year": 1999,
        "privacy_protected_standard": True,
        "description": "Primary domain of X social platform.",
    },
    "cloudflare.com": {
        "entity": "Cloudflare Inc.",
        "category": "CDN & Web Security",
        "authority": "HIGH",
        "established_year": 2009,
        "privacy_protected_standard": True,
        "description": "Global internet security and reverse proxy provider.",
    },
}


class WebHistoryScraper:
    """Evaluates Web History, AEO (Answer Engine Optimization) presence,
    and internet footprint authority for a given target domain.
    """

    def __init__(self):
        pass

    def _extract_domain(self, url_or_domain: str) -> str:
        if not url_or_domain:
            return ""
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            hostname = (parsed.hostname or "").lower().strip(".")
        else:
            hostname = url_or_domain.lower().strip(".").split("/")[0]

        parts = hostname.split(".")
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "edu", "org", "net", "ac") and len(parts[-1]) <= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return hostname

    def lookup_footprint(self, url_or_domain: str) -> AnalyzerResult:
        start_time = time.perf_counter()
        domain = self._extract_domain(url_or_domain)

        signals: List[SecuritySignal] = []

        # 1. Match known major entity
        matched_entity = None
        for known_domain, info in MAJOR_WEB_ENTITIES.items():
            if domain == known_domain or domain.endswith("." + known_domain):
                matched_entity = info
                break

        if matched_entity:
            signals.append(
                SecuritySignal(
                    source="web_history",
                    type="established_major_entity",
                    severity=SecuritySeverity.INFO,
                    description=f"Domain '{domain}' has major verified web history ({matched_entity['entity']})",
                    data=matched_entity,
                )
            )

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return AnalyzerResult(
                available=True,
                status="success",
                data={
                    "domain": domain,
                    "has_major_web_history": True,
                    "entity_name": matched_entity["entity"],
                    "web_authority": matched_entity["authority"],
                    "category": matched_entity["category"],
                    "established_year": matched_entity.get("established_year"),
                    "privacy_protected_standard": matched_entity.get("privacy_protected_standard", True),
                    "search_engine_footprint": f"Massive global footprint: {matched_entity['description']}",
                    "privacy_context": (
                        f"{matched_entity['entity']} routinely utilizes WHOIS/RDAP privacy redaction "
                        "for corporate security, spam prevention, and personnel protection. "
                        "Redacted registration details are standard legitimate practice for this entity."
                    ),
                },
                signals=signals,
                execution_time_ms=elapsed_ms,
            )

        # 2. General domain evaluation (not in top curated list)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return AnalyzerResult(
            available=True,
            status="unindexed_entity",
            data={
                "domain": domain,
                "has_major_web_history": False,
                "entity_name": None,
                "web_authority": "UNRANKED_OR_PRIVATE",
                "category": "General Web Domain",
                "privacy_protected_standard": False,
                "search_engine_footprint": "Standard or private web footprint without major global entity presence.",
                "privacy_context": "Domain must be evaluated strictly based on ML, SSL/TLS, and Threat Intelligence signals.",
            },
            signals=signals,
            execution_time_ms=elapsed_ms,
        )

