import re
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity


class RDAPClient:
    """Resilient client for querying ICANN RDAP (Registration Data Access Protocol)
    for domain registration age, registrar, and privacy status.
    """

    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
        self.base_url = "https://rdap.org/domain"

    def _extract_domain(self, url_or_domain: str) -> str:
        if not url_or_domain:
            return ""
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            hostname = (parsed.hostname or "").lower().strip(".")
        else:
            hostname = url_or_domain.lower().strip(".").split("/")[0]

        # Extract registrable domain (e.g. sub.example.com -> example.com)
        parts = hostname.split(".")
        if len(parts) >= 2:
            # Handle two-part TLDs like .co.uk, .com.au, .gov.in
            if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "edu", "org", "net", "ac") and len(parts[-1]) <= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return hostname

    def lookup_domain(self, url_or_domain: str) -> AnalyzerResult:
        start_time = time.perf_counter()
        domain = self._extract_domain(url_or_domain)

        if not domain or "." not in domain:
            return AnalyzerResult(
                available=False,
                status="not_applicable",
                data={"domain": domain, "reason": "No valid domain extracted"},
                execution_time_ms=0.0,
            )

        endpoint = f"{self.base_url}/{domain}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "User-Agent": "Aegis-Security-Engine/1.0",
                "Accept": "application/json",
            },
            method="GET",
        )

        signals: List[SecuritySignal] = []

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))

            # Parse event dates (registration, expiration, last changed)
            events = {}
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date_str = ev.get("eventDate", "")
                if action and date_str:
                    events[action] = date_str

            reg_date_str = events.get("registration") or events.get("created")
            exp_date_str = events.get("expiration")
            domain_age_days: Optional[int] = None

            if reg_date_str:
                try:
                    # Clean ISO date (strip trailing Z or timezone offset if needed)
                    clean_reg = reg_date_str.replace("Z", "+00:00")
                    reg_dt = datetime.fromisoformat(clean_reg)
                    now_dt = datetime.now(timezone.utc)
                    domain_age_days = max(0, (now_dt - reg_dt).days)
                except Exception:
                    domain_age_days = None

            # Extract registrar info
            registrar_name = None
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and item and item[0] == "fn":
                                registrar_name = item[3] if len(item) > 3 else None
                                break

            # Detect privacy redaction (e.g. Meta, Instagram, Cloudflare, Google hide WHOIS info)
            privacy_redacted = False
            registrant_roles = [r for ent in entities for r in ent.get("roles", [])]
            if "registrant" not in registrant_roles:
                privacy_redacted = True

            status_codes = data.get("status", [])

            # Check if domain was created very recently (< 14 days old is suspicious for high-risk targets)
            if domain_age_days is not None and domain_age_days < 14:
                signals.append(
                    SecuritySignal(
                        source="rdap",
                        type="newly_registered_domain",
                        severity=SecuritySeverity.HIGH,
                        description=f"Domain '{domain}' was registered only {domain_age_days} days ago",
                        data={"domain_age_days": domain_age_days, "registration_date": reg_date_str},
                    )
                )
            elif domain_age_days is not None and domain_age_days < 60:
                signals.append(
                    SecuritySignal(
                        source="rdap",
                        type="young_domain",
                        severity=SecuritySeverity.LOW,
                        description=f"Domain '{domain}' is young ({domain_age_days} days old)",
                        data={"domain_age_days": domain_age_days},
                    )
                )

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return AnalyzerResult(
                available=True,
                status="success",
                data={
                    "domain": domain,
                    "registered": True,
                    "registration_date": reg_date_str,
                    "expiration_date": exp_date_str,
                    "domain_age_days": domain_age_days,
                    "registrar": registrar_name,
                    "privacy_redacted": privacy_redacted,
                    "status_codes": status_codes,
                    "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if isinstance(ns, dict)],
                },
                signals=signals,
                execution_time_ms=elapsed_ms,
            )

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if e.code == 404:
                # 404 in RDAP means domain not found / unregistered / TLD unsupported
                return AnalyzerResult(
                    available=True,
                    status="not_found",
                    data={
                        "domain": domain,
                        "registered": False,
                        "privacy_redacted": True,
                        "note": "Domain not indexed in public RDAP bootstrap",
                    },
                    execution_time_ms=elapsed_ms,
                )
            return AnalyzerResult(
                available=False,
                status="http_error",
                data={"domain": domain, "http_status": e.code, "privacy_redacted": True},
                errors=[f"RDAP query failed with HTTP {e.code}"],
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            # Graceful error containment: if RDAP fails or times out, never block the analysis
            return AnalyzerResult(
                available=False,
                status="timeout" if "timed out" in str(e).lower() else "error",
                data={"domain": domain, "privacy_redacted": True},
                errors=[f"RDAP lookup failed: {str(e)}"],
                execution_time_ms=elapsed_ms,
            )

