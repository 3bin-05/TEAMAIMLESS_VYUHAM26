import os
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Set, Optional, List

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from .base import ThreatIntelProvider
from .official_domains import check_official_domain
from .brand_lookalike import detect_brand_lookalike
from cybersec_tools.reputation.virustotal import VirusTotalClient
from cybersec_tools.reputation.safe_browsing import GoogleSafeBrowsingClient

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Integrated threat intelligence provider combining local blocklists/allowlists,
    official restricted TLD verification, brand lookalike/typosquatting detection,
    VirusTotal API v3, and Google Safe Browsing API v4.
    """

    def __init__(
        self,
        allowlist_path: Optional[Path] = None,
        blocklist_path: Optional[Path] = None,
        enable_external_feeds: bool = True,
    ):
        self.allowlist_path = (
            allowlist_path if allowlist_path else DEFAULT_CONFIG_DIR / "allowlist.txt"
        )
        self.blocklist_path = (
            blocklist_path if blocklist_path else DEFAULT_CONFIG_DIR / "blocklist.txt"
        )

        self.allowlist: Set[str] = self._load_list(self.allowlist_path)
        self.blocklist: Set[str] = self._load_list(self.blocklist_path)
        self.enable_external_feeds = enable_external_feeds

        self.vt_client = VirusTotalClient()
        self.gsb_client = GoogleSafeBrowsingClient()

    def _load_list(self, path: Path) -> Set[str]:
        entries: Set[str] = set()
        if not path.exists():
            return entries

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line.lower().strip("."))
        except Exception:
            pass
        return entries

    def _match_domain_boundary(self, hostname: str, target_list: Set[str]) -> Optional[str]:
        if not hostname or not target_list:
            return None

        h = hostname.lower().strip(".")
        if h in target_list:
            return h

        # Check subdomains (e.g., "sub.badexample.com" matches "badexample.com")
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in target_list:
                return parent_domain

        return None

    def lookup_domain(self, domain: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not domain or not isinstance(domain, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["Domain string must be a non-empty string"],
                execution_time_ms=0.0,
            )

        hostname = domain.lower().strip(".")
        signals: List[SecuritySignal] = []

        # 1. Check local blocklist
        block_match = self._match_domain_boundary(hostname, self.blocklist)
        if block_match:
            signals.append(
                SecuritySignal(
                    source="threat_intel",
                    type="known_malicious_match",
                    severity=SecuritySeverity.CRITICAL,
                    description=f"Domain '{hostname}' matched known malicious blocklist entry '{block_match}'",
                    data={"matched_domain": block_match, "list": "blocklist"},
                )
            )

        # 2. Check local allowlist
        allow_match = self._match_domain_boundary(hostname, self.allowlist)
        if allow_match:
            signals.append(
                SecuritySignal(
                    source="threat_intel",
                    type="allowlisted_domain",
                    severity=SecuritySeverity.INFO,
                    description=f"Domain '{hostname}' matched trusted allowlist entry '{allow_match}'",
                    data={"matched_domain": allow_match, "list": "allowlist"},
                )
            )

        # 3. Check official/restricted domain that cannot be bought by the public (.gov, .mil, .int, .edu, .gob, .police, .bank, .insurance, etc.)
        official_info = check_official_domain(hostname)
        if official_info:
            signals.append(
                SecuritySignal(
                    source="threat_intel",
                    type="official_restricted_domain",
                    severity=SecuritySeverity.INFO,
                    description=f"Domain '{hostname}' is an official domain using restricted TLD '.{official_info.tld}' ({official_info.description})",
                    data={
                        "matched_tld": official_info.tld,
                        "category": official_info.category,
                        "name": official_info.name,
                        "description": official_info.description,
                        "restricted_registration": True,
                    },
                )
            )

        # 4. Check Brand Look-alike / Typosquatting / Combosquatting
        brand_lookalike = None
        if not official_info:
            brand_lookalike = detect_brand_lookalike(hostname)
            if brand_lookalike and brand_lookalike.get("detected"):
                signals.append(
                    SecuritySignal(
                        source="threat_intel",
                        type="brand_impersonation_typosquat",
                        severity=SecuritySeverity.CRITICAL,
                        description=brand_lookalike["reason"],
                        data=brand_lookalike,
                    )
                )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        matched = block_match is not None or allow_match is not None or official_info is not None or brand_lookalike is not None

        return AnalyzerResult(
            available=True,
            status="success",
            data={
                "domain": hostname,
                "matched": matched,
                "is_blocked": block_match is not None,
                "is_allowlisted": allow_match is not None,
                "is_official_domain": official_info is not None,
                "official_info": official_info.to_dict() if official_info else None,
                "brand_lookalike": brand_lookalike,
                "block_match": block_match,
                "allow_match": allow_match,
                "source": "local_threat_intel",
            },
            signals=signals,
            errors=[],
            execution_time_ms=elapsed_ms,
        )

    def lookup_url(self, url: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not url or not isinstance(url, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL string must be a non-empty string"],
                execution_time_ms=0.0,
            )

        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            hostname = (parsed.hostname or "").lower().strip(".")
        except Exception as e:
            return AnalyzerResult(
                available=False,
                status="error",
                errors=[f"Failed to parse URL: {str(e)}"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        # Perform base domain lookups (blocklist, allowlist, official restricted TLD, brand lookalike)
        res = self.lookup_domain(hostname)
        res.data["url"] = url

        # External Threat Feeds: VirusTotal & Google Safe Browsing
        vt_data = None
        gsb_data = None

        if self.enable_external_feeds:
            # 1. VirusTotal API lookup
            try:
                vt_data = self.vt_client.lookup_url(url)
                res.data["virustotal"] = vt_data
                if vt_data.get("is_malicious"):
                    res.signals.append(
                        SecuritySignal(
                            source="threat_intel",
                            type="virustotal_malicious",
                            severity=SecuritySeverity.CRITICAL,
                            description=f"VirusTotal detected {vt_data.get('malicious')} security engines flagging this URL as malicious",
                            data=vt_data,
                        )
                    )
                elif vt_data.get("harmless", 0) >= 3 and vt_data.get("malicious", 0) == 0:
                    res.signals.append(
                        SecuritySignal(
                            source="threat_intel",
                            type="virustotal_clean",
                            severity=SecuritySeverity.INFO,
                            description=f"VirusTotal reputation clean ({vt_data.get('harmless')} security vendors confirmed harmless)",
                            data=vt_data,
                        )
                    )
            except Exception as e:
                res.errors.append(f"VirusTotal check failed: {str(e)}")

            # 2. Google Safe Browsing API lookup
            try:
                gsb_data = self.gsb_client.lookup_url(url)
                res.data["safe_browsing"] = gsb_data
                if gsb_data.get("is_threat"):
                    threats = ", ".join(gsb_data.get("threat_types", [])) or "Threat detected"
                    res.signals.append(
                        SecuritySignal(
                            source="threat_intel",
                            type="google_safebrowsing_threat",
                            severity=SecuritySeverity.CRITICAL,
                            description=f"Google Safe Browsing flagged threat: {threats}",
                            data=gsb_data,
                        )
                    )
            except Exception as e:
                res.errors.append(f"Google Safe Browsing check failed: {str(e)}")

        res.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return res
