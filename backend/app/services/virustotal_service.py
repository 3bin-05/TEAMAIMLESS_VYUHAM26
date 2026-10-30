import asyncio
from datetime import datetime, timezone
import logging
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis")


async def check_virustotal(url: str, max_retries: int = 2, retry_delay: float = 1.0) -> dict:
    """
    Submits a URL to VirusTotal API v3, retrieves analysis ID, and polls for results.
    Handles pending analyses, rate limits (HTTP 429), authentication failures (401/403),
    timeouts, and malformed responses.
    """
    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key:
        return {
            "status": "unavailable",
            "reason": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    checked_at = datetime.now(timezone.utc).isoformat()

    try:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT) as client:
            # 1. Submit URL for analysis
            submission_resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": str(url).strip()}
            )

            if submission_resp.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded on submission (HTTP 429)")
                return {
                    "status": "unavailable",
                    "reason": "VirusTotal rate limit exceeded (HTTP 429)",
                    "checked_at": checked_at
                }

            if submission_resp.status_code in (401, 403):
                logger.warning(f"VirusTotal authentication failure (HTTP {submission_resp.status_code})")
                return {
                    "status": "unavailable",
                    "reason": f"VirusTotal API key invalid or unauthorized (HTTP {submission_resp.status_code})",
                    "checked_at": checked_at
                }

            submission_resp.raise_for_status()
            sub_data = submission_resp.json()
            analysis_id = sub_data.get("data", {}).get("id")

            if not analysis_id:
                return {
                    "status": "failed",
                    "reason": "VirusTotal response missing analysis ID",
                    "checked_at": checked_at
                }

            # 2. Poll for completed analysis status
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            stats = None
            analysis_status = "queued"

            for attempt in range(max_retries + 1):
                analysis_resp = await client.get(analysis_url, headers=headers)

                if analysis_resp.status_code == 429:
                    logger.warning("VirusTotal rate limit hit during polling")
                    return {
                        "status": "unavailable",
                        "reason": "VirusTotal rate limit exceeded during polling (HTTP 429)",
                        "checked_at": checked_at
                    }

                analysis_resp.raise_for_status()
                analysis_json = analysis_resp.json()

                attributes = analysis_json.get("data", {}).get("attributes", {})
                analysis_status = attributes.get("status", "queued")

                if analysis_status == "completed":
                    stats = attributes.get("stats", {})
                    break

                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)

            # If still not completed after bounded retries, report pending
            if analysis_status != "completed" or stats is None:
                return {
                    "status": "pending",
                    "analysis_id": analysis_id,
                    "reason": f"Analysis still in progress on VirusTotal (status: {analysis_status})",
                    "checked_at": checked_at
                }

            return {
                "status": "completed",
                "analysis_id": analysis_id,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "checked_at": checked_at
            }

    except httpx.TimeoutException:
        logger.warning("VirusTotal request timed out")
        return {
            "status": "unavailable",
            "reason": "VirusTotal request timed out",
            "checked_at": checked_at
        }
    except Exception as exc:
        logger.warning(f"VirusTotal query failed: {exc}")
        return {
            "status": "failed",
            "reason": str(exc),
            "checked_at": checked_at
        }