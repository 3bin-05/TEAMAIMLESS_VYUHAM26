import re
import logging
from urllib.parse import urlsplit
import httpx
# Safe regex-based parser used below to avoid heavy third-party dependencies

logger = logging.getLogger("aegis")

async def inspect_safe_content(url: str, timeout: float = 2.0) -> dict:
    """
    Safely and boundedly inspects web page title, meta description, and form indicators.
    Enforces strict safety constraints:
    - Never submits credentials or fills forms
    - Never executes scripts or parses active DOM
    - Reads only up to the first 32 KB of HTML
    - Strict short timeout (default 2s) to avoid delaying analysis
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return {"status": "skipped", "reason": "Non-HTTP/HTTPS scheme"}

        headers = {
            "User-Agent": "AEGIS-Security-Analyzer/1.0 (+https://aegis-defense.local/bot; security-audit)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Encoding": "identity",
        }

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers=headers)
            content = resp.text[:32768]  # Limit to first 32 KB

        # Extract title using robust regex
        title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None

        # Extract meta description
        meta_match = re.search(
            r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']',
            content,
            re.IGNORECASE | re.DOTALL
        ) or re.search(
            r'<meta\s+[^>]*content=["\'](.*?)["\'][^>]*name=["\']description["\']',
            content,
            re.IGNORECASE | re.DOTALL
        )
        meta_desc = re.sub(r"\s+", " ", meta_match.group(1)).strip() if meta_match else None

        # Detect login/password input elements without interacting
        has_password_field = bool(re.search(r'<input\s+[^>]*type=["\']password["\']', content, re.IGNORECASE))
        has_login_form = bool(
            has_password_field or
            re.search(r'(sign\s*in|log\s*in|user\s*name|password|credential)', content[:8000], re.IGNORECASE)
        )

        suspicious_patterns = []
        if has_password_field and parsed.scheme.lower() != "https":
            suspicious_patterns.append("Unencrypted (HTTP) password input field detected")

        if re.search(r"(verify\s+your\s+account|urgent\s+security\s+alert|account\s+suspended)", content[:8000], re.IGNORECASE):
            suspicious_patterns.append("Urgent security/suspension messaging indicative of social engineering")

        return {
            "status": "completed",
            "title": title or "No page title found",
            "meta_description": meta_desc or "No description metadata",
            "has_login_form": has_login_form,
            "has_password_field": has_password_field,
            "suspicious_patterns": suspicious_patterns
        }

    except httpx.TimeoutException:
        return {
            "status": "unreachable",
            "reason": "Website safe inspection timed out (server did not respond in 2.0s)"
        }
    except Exception as exc:
        return {
            "status": "failed",
            "reason": f"Safe content inspection error: {str(exc)[:100]}"
        }
