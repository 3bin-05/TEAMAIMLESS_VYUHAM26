from datetime import datetime, timezone
import logging
from urllib.parse import urlsplit
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis")

# Authoritative IANA RDAP server mappings for common TLDs
IANA_BOOTSTRAP_SERVERS: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "info": "https://rdap.afilias.net/rdap/domain/",
    "io": "https://rdap.identitydigital.services/rdap/domain/",
    "me": "https://rdap.nic.me/domain/",
    "in": "https://rdap.registry.in/domain/",
    "ca": "https://rdap.ca.fury.ca/rdap/domain/",
    "eu": "https://rdap.eurid.eu/domain/",
    "de": "https://rdap.denic.de/domain/",
    "uk": "https://rdap.nominet.uk/domain/",
    "fr": "https://rdap.nic.fr/domain/",
    "nl": "https://rdap.sidn.nl/domain/",
    "br": "https://rdap.registro.br/domain/"
}


def get_authoritative_rdap_url(domain: str) -> str:
    """
    Identifies the authoritative RDAP endpoint for the domain's TLD using
    IANA bootstrap mappings, falling back to RDAP_BASE_URL (rdap.org).
    """
    clean_domain = domain.strip().lower()
    tld = clean_domain.split(".")[-1] if "." in clean_domain else ""

    if tld in IANA_BOOTSTRAP_SERVERS:
        return f"{IANA_BOOTSTRAP_SERVERS[tld]}{clean_domain}"

    # Default to rdap.org redirector or configured base URL
    base = settings.RDAP_BASE_URL.rstrip("/")
    return f"{base}/{clean_domain}"


def parse_iso_date(date_str: str | None) -> datetime | None:
    """Parses standard ISO 8601 RDAP event timestamp."""
    if not date_str:
        return None
    try:
        clean = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def extract_entity_name(entity: dict) -> str | None:
    """Extracts formatted name (fn) from RDAP vcardArray."""
    try:
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                    return str(prop[3])
    except Exception:
        pass
    return None


async def check_rdap(domain: str) -> dict:
    """
    Queries authoritative RDAP servers for domain intelligence.
    Extracts creation, expiration, registrar, domain age in days, status, and nameservers.
    """
    clean_domain = domain.strip().lower()
    if not clean_domain:
        return {
            "status": "failed",
            "reason": "Empty domain provided"
        }

    request_url = get_authoritative_rdap_url(clean_domain)

    try:
        async with httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT,
            follow_redirects=True
        ) as client:
            headers = {"Accept": "application/rdap+json, application/json"}
            response = await client.get(request_url, headers=headers)

            if response.status_code == 404:
                return {
                    "status": "completed",
                    "domain": clean_domain,
                    "registered": False,
                    "reason": "Domain not found in registry (HTTP 404)",
                    "creation_date": None,
                    "domain_age_days": None,
                    "expiration_date": None,
                    "last_updated": None,
                    "registrar": None,
                    "domain_status": [],
                    "nameservers": []
                }

            if response.status_code == 429:
                return {
                    "status": "unavailable",
                    "reason": "RDAP server rate limit exceeded (HTTP 429)"
                }

            response.raise_for_status()
            data = response.json()

        # Parse event dates
        events = {}
        for item in data.get("events", []):
            action = item.get("eventAction")
            date_val = item.get("eventDate")
            if action and date_val:
                events[action.lower()] = date_val

        creation_date = events.get("registration") or events.get("created")
        expiration_date = events.get("expiration") or events.get("expired")
        last_updated = events.get("last changed") or events.get("last update")

        # Calculate domain age in days if registration date is available
        domain_age_days = None
        if creation_date:
            dt_created = parse_iso_date(creation_date)
            if dt_created:
                now_utc = datetime.now(timezone.utc)
                domain_age_days = max(0, (now_utc - dt_created).days)

        # Parse registrar and public registrant
        registrar = None
        registrant = None

        for entity in data.get("entities", []):
            roles = [r.lower() for r in entity.get("roles", [])]
            if "registrar" in roles and registrar is None:
                registrar = extract_entity_name(entity)
            if "registrant" in roles and registrant is None:
                registrant = extract_entity_name(entity)

        # Parse nameservers
        nameservers = []
        for ns in data.get("nameservers", []):
            ldh = ns.get("ldhName")
            if ldh:
                nameservers.append(str(ldh).lower())

        return {
            "status": "completed",
            "domain": data.get("ldhName", clean_domain),
            "registered": True,
            "creation_date": creation_date,
            "domain_age_days": domain_age_days,
            "expiration_date": expiration_date,
            "last_updated": last_updated,
            "registrar": registrar,
            "registrant": registrant,
            "domain_status": data.get("status", []),
            "nameservers": nameservers
        }

    except httpx.TimeoutException:
        logger.warning(f"RDAP query timed out for domain: {clean_domain}")
        return {
            "status": "unavailable",
            "reason": f"RDAP query timed out for {clean_domain}"
        }
    except Exception as exc:
        logger.warning(f"RDAP query failed for domain {clean_domain}: {exc}")
        return {
            "status": "failed",
            "reason": str(exc)
        }