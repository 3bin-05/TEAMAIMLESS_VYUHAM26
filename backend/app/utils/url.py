import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def validate_url_syntax(url: str) -> tuple[bool, str]:
    """
    Validates that a URL is syntactically sound and safe for analysis:
    - Non-empty, non-whitespace string.
    - Only 'http' and 'https' schemes are accepted.
    - Hostname must be present and well-formed.
    - Rejects malformed schemes, empty authorities, and invalid hostnames.
    - Distinguishes syntactically valid URLs (even if suspicious) from invalid ones.
    """
    raw = str(url).strip()
    if not raw:
        return False, "URL cannot be empty."

    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    scheme = parsed.scheme.lower()
    if not scheme:
        return False, "Missing URL scheme. Only HTTP and HTTPS are permitted."

    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname or authority."

    hostname = hostname.lower()

    # Validate IP address if hostname is numeric/colon-separated
    try:
        ipaddress.ip_address(hostname)
        return True, ""
    except ValueError:
        pass

    # Validate domain name syntax
    if ".." in hostname or hostname.startswith(".") or hostname.endswith("."):
        return False, "Invalid hostname: consecutive or leading/trailing dots."

    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False, "Invalid hostname: label length must be between 1 and 63 characters."
        if label.startswith("-") or label.endswith("-"):
            return False, "Invalid hostname: label cannot start or end with a hyphen."
        if not re.match(r"^[a-z0-9-]+$", label):
            return False, f"Invalid hostname: label '{label}' contains invalid characters."

    # Validate port if specified
    try:
        if parsed.port is not None:
            if not (1 <= parsed.port <= 65535):
                return False, f"Invalid port number: {parsed.port}"
    except ValueError as exc:
        return False, f"Invalid port in URL: {exc}"

    return True, ""


def normalize_url(url: str) -> str:
    """
    Normalizes a given URL for consistent hashing, database lookups, and analysis.
    Lowercases scheme and host, ensures path defaults to '/', preserves query.
    """
    raw = str(url).strip()
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower() or "http"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def extract_domain(url: str) -> str:
    """
    Extracts the lowercase hostname/domain from a URL.
    """
    try:
        parsed = urlsplit(str(url).strip())
        return (parsed.hostname or "").lower()
    except Exception:
        return ""

