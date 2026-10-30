import os
import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional


class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing API v4 URL threat verification."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.5):
        self.api_key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
        self.timeout = timeout
        self.endpoint_template = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Query Google Safe Browsing v4 threat feed for malware, social engineering, and harmful software.

        Returns:
            Dict containing threat match status, detected threat types, and metadata.
        """
        if not self.api_key:
            return {
                "available": False,
                "status": "missing_api_key",
                "is_threat": False,
                "matches": [],
                "threat_types": [],
            }

        start_time = time.perf_counter()
        endpoint = self.endpoint_template.format(key=self.api_key)

        payload = {
            "client": {
                "clientId": "aegis-cyber-engine",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url.strip()}],
            },
        }

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Phishing-Engine/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                matches: List[Dict[str, Any]] = body.get("matches", [])
                threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                return {
                    "available": True,
                    "status": "success",
                    "is_threat": len(matches) > 0,
                    "matches": matches,
                    "threat_types": threat_types,
                    "latency_ms": elapsed_ms,
                }

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "available": False,
                "status": f"http_error_{e.code}",
                "error": str(e),
                "is_threat": False,
                "matches": [],
                "threat_types": [],
                "latency_ms": elapsed_ms,
            }
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "available": False,
                "status": "lookup_error",
                "error": str(e),
                "is_threat": False,
                "matches": [],
                "threat_types": [],
                "latency_ms": elapsed_ms,
            }
