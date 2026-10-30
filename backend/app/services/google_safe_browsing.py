from datetime import datetime, timezone
import logging
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis")


async def check_google_safe_browsing(url: str) -> dict:
    """
    Queries Google Safe Browsing Lookup API (v4) for known threat classifications.
    Handles rate limits, invalid keys, timeouts, and network failures gracefully.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    if not api_key:
        return {
            "status": "unavailable",
            "reason": "Google Safe Browsing API key not configured"
        }

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    payload = {
        "client": {
            "clientId": "aegis-defense",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": str(url).strip()}]
        }
    }

    checked_at = datetime.now(timezone.utc).isoformat()

    try:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT) as client:
            # Pass API key as query parameter without logging it
            response = await client.post(
                endpoint,
                params={"key": api_key},
                json=payload
            )

            if response.status_code == 429:
                logger.warning("Google Safe Browsing API rate limit exceeded (HTTP 429)")
                return {
                    "status": "unavailable",
                    "reason": "Google Safe Browsing rate limit exceeded (HTTP 429)",
                    "checked_at": checked_at
                }

            if response.status_code in (400, 403):
                logger.warning(f"Google Safe Browsing authentication/request error (HTTP {response.status_code})")
                return {
                    "status": "unavailable",
                    "reason": f"Google Safe Browsing API key invalid or unauthorized (HTTP {response.status_code})",
                    "checked_at": checked_at
                }

            response.raise_for_status()
            data = response.json()

        matches = data.get("matches", [])
        threat_detected = len(matches) > 0

        parsed_matches = []
        for m in matches:
            parsed_matches.append({
                "threat_type": m.get("threatType"),
                "platform_type": m.get("platformType"),
                "threat_entry_type": m.get("threatEntryType")
            })

        return {
            "status": "completed",
            "threat_detected": threat_detected,
            "matches": parsed_matches,
            "match_count": len(parsed_matches),
            "checked_at": checked_at
        }

    except httpx.TimeoutException:
        logger.warning("Google Safe Browsing query timed out")
        return {
            "status": "unavailable",
            "reason": "Google Safe Browsing request timed out",
            "checked_at": checked_at
        }
    except Exception as exc:
        logger.warning(f"Google Safe Browsing query failed: {exc}")
        return {
            "status": "failed",
            "reason": str(exc),
            "checked_at": checked_at
        }