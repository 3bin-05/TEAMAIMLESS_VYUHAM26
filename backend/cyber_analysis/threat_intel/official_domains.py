import re
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import tldextract


@dataclass
class OfficialDomainInfo:
    is_official: bool
    tld: str
    category: str
    name: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Single-level official/restricted TLD definitions
RESTRICTED_TLDS: Dict[str, Dict[str, str]] = {
    "gov": {
        "category": "Government",
        "name": "Government Entity (.gov)",
        "description": "Restricted exclusively to verified U.S. government entities and agencies. Cannot be registered by the public.",
    },
    "mil": {
        "category": "Military",
        "name": "U.S. Military (.mil)",
        "description": "Restricted exclusively to the United States Department of Defense and military organizations. Cannot be registered by the public.",
    },
    "int": {
        "category": "International Organization",
        "name": "International Treaty Organization (.int)",
        "description": "Restricted exclusively to international treaty-based organizations and intergovernmental bodies. Cannot be registered by the public.",
    },
    "edu": {
        "category": "Education",
        "name": "Accredited Educational Institution (.edu)",
        "description": "Restricted exclusively to eligible accredited postsecondary educational institutions. Cannot be registered by the public.",
    },
    "gob": {
        "category": "Government",
        "name": "Government Entity (.gob)",
        "description": "Restricted to official government domains in relevant jurisdictions. Cannot be registered by the public.",
    },
    "police": {
        "category": "Law Enforcement",
        "name": "Law Enforcement (.police)",
        "description": "Restricted to verified police departments and law enforcement agencies in relevant jurisdictions.",
    },
    "bank": {
        "category": "Banking",
        "name": "Verified Banking Institution (.bank)",
        "description": "Restricted exclusively to verified, authenticated banking institutions under strict fTLD registry verification. Cannot be registered by the public.",
    },
    "insurance": {
        "category": "Insurance",
        "name": "Verified Insurance Institution (.insurance)",
        "description": "Restricted exclusively to verified and authenticated insurance organizations under strict fTLD registry verification. Cannot be registered by the public.",
    },
}

# Regex patterns for country-code and multi-level official suffixes
# e.g., .gov.uk, .gov.in, .edu.au, .ac.uk, .gob.mx, .gouv.fr, .police.uk, .mil.uk
CC_OFFICIAL_PATTERNS = [
    # Government ccTLD patterns
    (
        re.compile(r"^(gov|gob|gouv|gc|fed|state)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Government",
        "Official Government Domain",
        "Restricted to verified national or regional government entities. Cannot be registered by the general public.",
    ),
    (
        re.compile(r"^[a-z0-9-]+\.(gov|gob|gouv)\.[a-z]{2,3}$", re.IGNORECASE),
        "Government",
        "Official Government Domain",
        "Restricted to verified government entities in relevant jurisdiction.",
    ),
    (
        re.compile(r"^nic\.[a-z]{2,3}$", re.IGNORECASE),
        "Government",
        "National Informatics Centre / Official Registry",
        "Restricted to official governmental informatics network.",
    ),
    # Military ccTLD patterns
    (
        re.compile(r"^(mil|mod|def)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Military",
        "Official Military / Armed Forces",
        "Restricted exclusively to verified military and defense forces. Cannot be registered by the public.",
    ),
    # Educational ccTLD patterns (.edu.xx, .ac.xx)
    (
        re.compile(r"^(edu|ac)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Education",
        "Accredited Educational / Academic Institution",
        "Restricted exclusively to accredited universities, colleges, and academic institutions.",
    ),
    # Law enforcement ccTLD patterns (.police.xx)
    (
        re.compile(r"^police\.[a-z]{2,3}$", re.IGNORECASE),
        "Law Enforcement",
        "Law Enforcement / Police Department",
        "Restricted to verified police departments and law enforcement authorities.",
    ),
]


def check_official_domain(hostname_or_url: str) -> Optional[OfficialDomainInfo]:
    """Check if a hostname or URL belongs to an official, restricted TLD that cannot be registered by the public.

    Args:
        hostname_or_url: Hostname (e.g. 'irs.gov', 'chase.bank', 'ox.ac.uk') or full URL.

    Returns:
        OfficialDomainInfo if matched, or None.
    """
    if not hostname_or_url or not isinstance(hostname_or_url, str):
        return None

    raw = hostname_or_url.strip().lower()
    if "://" in raw:
        # Extract host from URL
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip(".")

    if not raw:
        return None

    # Extract TLD / suffix
    extracted = tldextract.extract(raw)
    suffix = extracted.suffix.lower().strip(".")
    domain = extracted.domain.lower()

    # 1. Exact match on single-level restricted TLDs (e.g. .gov, .mil, .int, .edu, .gob, .police, .bank, .insurance)
    if suffix in RESTRICTED_TLDS:
        info = RESTRICTED_TLDS[suffix]
        return OfficialDomainInfo(
            is_official=True,
            tld=suffix,
            category=info["category"],
            name=info["name"],
            description=info["description"],
        )

    # 2. Check multi-level / ccTLD official patterns against the suffix
    for pattern, cat, name, desc in CC_OFFICIAL_PATTERNS:
        if pattern.match(suffix):
            return OfficialDomainInfo(
                is_official=True,
                tld=suffix,
                category=cat,
                name=f"{name} (.{suffix})",
                description=desc,
            )

    # 3. Fallback: Check parts of hostname if tldextract didn't separate custom suffixes
    parts = raw.split(".")
    if len(parts) >= 2:
        last_part = parts[-1]
        if last_part in RESTRICTED_TLDS:
            info = RESTRICTED_TLDS[last_part]
            return OfficialDomainInfo(
                is_official=True,
                tld=last_part,
                category=info["category"],
                name=info["name"],
                description=info["description"],
            )

        last_two = f"{parts[-2]}.{parts[-1]}"
        for pattern, cat, name, desc in CC_OFFICIAL_PATTERNS:
            if pattern.match(last_two):
                return OfficialDomainInfo(
                    is_official=True,
                    tld=last_two,
                    category=cat,
                    name=f"{name} (.{last_two})",
                    description=desc,
                )

    return None
