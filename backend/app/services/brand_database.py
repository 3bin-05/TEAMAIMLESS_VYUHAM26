"""
AEGIS DomainShield — Brand Intelligence Database & Confusable Mappings.
Provides curated, maintainable brand intelligence and authoritative official domains.
"""

from typing import Any

# Curated, authoritative brand catalog
# Official domains are verified against IANA registries and legitimate corporate namespaces.
BRAND_CATALOG: dict[str, dict[str, Any]] = {
    "google": {
        "name": "Google",
        "canonical_key": "google",
        "official_domains": {
            "google.com", "google.co.uk", "google.ca", "google.de", "google.fr",
            "google.co.jp", "google.com.br", "google.co.in", "google.es", "google.it",
            "youtube.com", "gmail.com", "android.com", "gstatic.com", "googleapis.com",
            "googledrive.com", "googleusercontent.com", "chrome.com"
        },
        "aliases": ["google", "gmail", "youtube"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "microsoft": {
        "name": "Microsoft",
        "canonical_key": "microsoft",
        "official_domains": {
            "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
            "azure.com", "bing.com", "microsoftonline.com", "msn.com", "windows.com",
            "xbox.com", "onedrive.com", "sharepoint.com", "teams.microsoft.com"
        },
        "aliases": ["microsoft", "outlook", "office365", "azure", "onedrive"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "apple": {
        "name": "Apple",
        "canonical_key": "apple",
        "official_domains": {
            "apple.com", "icloud.com", "itunes.com", "apple-support.com", "me.com",
            "aaplimg.com", "appleid.apple.com"
        },
        "aliases": ["apple", "icloud", "itunes"],
        "min_similarity": 85.0,  # Short word requires higher similarity
        "high_confidence_similarity": 90.0
    },
    "amazon": {
        "name": "Amazon",
        "canonical_key": "amazon",
        "official_domains": {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp",
            "amazon.in", "amazon.fr", "amazon.es", "amazon.it", "aws.amazon.com",
            "primevideo.com", "media-amazon.com", "ssl-images-amazon.com"
        },
        "aliases": ["amazon", "primevideo", "aws"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "paypal": {
        "name": "PayPal",
        "canonical_key": "paypal",
        "official_domains": {
            "paypal.com", "paypal.me", "paypal-community.com", "venmo.com",
            "paypalobjects.com"
        },
        "aliases": ["paypal", "venmo"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "meta": {
        "name": "Meta",
        "canonical_key": "meta",
        "official_domains": {
            "meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fb.com",
            "messenger.com", "threads.net", "oculus.com"
        },
        "aliases": ["meta", "facebook", "instagram", "whatsapp"],
        "min_similarity": 85.0,
        "high_confidence_similarity": 90.0
    },
    "netflix": {
        "name": "Netflix",
        "canonical_key": "netflix",
        "official_domains": {
            "netflix.com", "nflxext.com", "nflxvideo.net", "nflximg.net"
        },
        "aliases": ["netflix"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "github": {
        "name": "GitHub",
        "canonical_key": "github",
        "official_domains": {
            "github.com", "github.io", "githubusercontent.com", "githubassets.com"
        },
        "aliases": ["github"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "openai": {
        "name": "OpenAI",
        "canonical_key": "openai",
        "official_domains": {
            "openai.com", "chatgpt.com"
        },
        "aliases": ["openai", "chatgpt"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "chase": {
        "name": "Chase Bank",
        "canonical_key": "chase",
        "official_domains": {
            "chase.com", "jpmorgan.com", "jpmorganchase.com"
        },
        "aliases": ["chase", "jpmorgan"],
        "min_similarity": 85.0,
        "high_confidence_similarity": 90.0
    },
    "bankofamerica": {
        "name": "Bank of America",
        "canonical_key": "bankofamerica",
        "official_domains": {
            "bankofamerica.com", "bofa.com", "merrilledge.com"
        },
        "aliases": ["bankofamerica", "bofa"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "canonical_key": "wellsfargo",
        "official_domains": {
            "wellsfargo.com"
        },
        "aliases": ["wellsfargo"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    },
    "linkedin": {
        "name": "LinkedIn",
        "canonical_key": "linkedin",
        "official_domains": {
            "linkedin.com", "licdn.com", "lnkd.in"
        },
        "aliases": ["linkedin", "licdn"],
        "min_similarity": 82.0,
        "high_confidence_similarity": 88.0
    }
}

# Deceptive security, authentication, and urgency keywords
SUSPICIOUS_SECURITY_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "logon",
    "verify", "verification", "security", "secure",
    "account", "support", "billing", "auth", "authentication",
    "update", "wallet", "recover", "recovery", "password",
    "portal", "confirm", "confirmation", "service", "banking",
    "alert", "protect", "validate", "validation", "identity"
}

# Homoglyph and Unicode confusable mapping (Cyrillic, Greek, Armenian, and Leetspeak to Latin canonicals)
CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j",
    "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "ѵ": "v", "в": "b",
    "п": "n", "т": "t", "г": "r", "м": "m", "н": "h",
    # Greek lookalikes
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "χ": "x",
    "ω": "w", "η": "n",
    # Armenian lookalikes
    "ո": "n", "օ": "o", "ս": "u",
    # Latin diacritics / special variants
    "ł": "l", "ı": "i", "ɑ": "a", "ɡ": "g", "ℓ": "l",
    "ø": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o",
    "ä": "a", "á": "a", "à": "a", "â": "a", "ã": "a",
    "é": "e", "è": "e", "ê": "e", "ë": "e",
    "í": "i", "ì": "i", "î": "i", "ï": "i",
    "ü": "u", "ú": "u", "ù": "u", "û": "u",
    "ñ": "n", "ç": "c",
    # Common numerical leetspeak substitutions
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s"
}

# Benign dictionary words that contain short brand names but are legitimate English words
BENIGN_SUBSTRING_WORDS: set[str] = {
    "pineapple", "pineapples", "snapple", "grapple", "appleton", "crabapple",
    "chasebank", "chaser", "chasers", "metal", "metallic", "metadata", "metaphor",
    "metabolism", "metamorphic", "microphone", "microscope", "microwave",
    "metropolitan", "amazonian", "amazonas", "goggles", "goggle", "anecdote", "appalachian"
}


def get_all_brands() -> dict[str, dict[str, Any]]:
    """Returns the active brand intelligence catalog."""
    return BRAND_CATALOG


def get_brand(brand_key: str) -> dict[str, Any] | None:
    """Retrieves brand configuration for a specific brand key."""
    return BRAND_CATALOG.get(brand_key.lower().strip())
