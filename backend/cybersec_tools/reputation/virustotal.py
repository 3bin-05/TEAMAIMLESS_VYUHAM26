import os
import time
import base64
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


class VirusTotalClient:
    """Client for VirusTotal API v3 URL reputation lookups."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.5):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.timeout = timeout
        self.base_url = "https://www.virustotal.com/api/v3/urls"

    def get_url_id(self, url: str) -> str:
        """Encode URL into VirusTotal v3 URL identifier (base64 URL-safe without padding)."""
        clean_url = url.strip()
        return base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("ascii").strip("=")

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Query VirusTotal API v3 for URL scan statistics and threat intelligence.

        Returns:
            Dict containing analysis stats, detection counts, and threat flags.
        """
        if not self.api_key:
            return {
                "available": False,
                "status": "missing_api_key",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "is_malicious": False,
            }

        start_time = time.perf_counter()
        url_id = self.get_url_id(url)
        endpoint = f"{self.base_url}/{url_id}"

        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Aegis-Phishing-Engine/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                attributes = payload.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                return {
                    "available": True,
                    "status": "success",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": malicious + suspicious + harmless + undetected,
                    "is_malicious": malicious > 0,
                    "is_suspicious": suspicious > 0 and malicious == 0,
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", []),
                    "latency_ms": elapsed_ms,
                }

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if e.code == 404:
                # URL is not yet known in VirusTotal corpus
                return {
                    "available": True,
                    "status": "not_in_dataset",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "total_engines": 0,
                    "is_malicious": False,
                    "latency_ms": elapsed_ms,
                }
            return {
                "available": False,
                "status": f"http_error_{e.code}",
                "error": str(e),
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "is_malicious": False,
                "latency_ms": elapsed_ms,
            }
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "available": False,
                "status": "lookup_error",
                "error": str(e),
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "is_malicious": False,
                "latency_ms": elapsed_ms,
            }
