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
    intended_org: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Comprehensive catalog of verified official and legally restricted domain namespaces
RESTRICTED_DOMAINS_CATALOG: Dict[str, Dict[str, str]] = {
    # 1. Government and military domains (USA, UK, India, Australia, Canada, France, Brazil, China, etc.)
    "gov": {
        "category": "Government",
        "name": "United States Government (.gov)",
        "intended_org": "Verified US government organisations",
        "description": "Restricted exclusively to verified U.S. federal, state, and local government organizations. Cannot be registered by the public.",
    },
    "mil": {
        "category": "Military",
        "name": "United States Military (.mil)",
        "intended_org": "Military organisations (USA)",
        "description": "Restricted exclusively to the United States Department of Defense and military services.",
    },
    "gov.uk": {
        "category": "Government",
        "name": "United Kingdom Government (.gov.uk)",
        "intended_org": "UK government organisations",
        "description": "Restricted exclusively to verified UK central and local government departments.",
    },
    "gov.in": {
        "category": "Government",
        "name": "Indian Government (.gov.in)",
        "intended_org": "Eligible Indian government organisations",
        "description": "Restricted exclusively to authenticated Indian union and state government entities under National Informatics Centre (NIC) oversight.",
    },
    "nic.in": {
        "category": "Government Infrastructure",
        "name": "National Informatics Centre (.nic.in)",
        "intended_org": "Indian National Informatics Centre and eligible government-related entities",
        "description": "Official infrastructure network of the Indian government's National Informatics Centre.",
    },
    "gov.au": {
        "category": "Government",
        "name": "Australian Government (.gov.au)",
        "intended_org": "Australian government entities",
        "description": "Restricted exclusively to verified Australian Commonwealth, State, and Territory government departments.",
    },
    "govt.nz": {
        "category": "Government",
        "name": "New Zealand Government (.govt.nz)",
        "intended_org": "New Zealand government entities",
        "description": "Restricted exclusively to verified New Zealand core Crown and public sector organizations.",
    },
    "gc.ca": {
        "category": "Government",
        "name": "Government of Canada (.gc.ca)",
        "intended_org": "Canadian government entities",
        "description": "Restricted exclusively to federal departments and agencies of the Government of Canada.",
    },
    "gouv.fr": {
        "category": "Government",
        "name": "French Government (.gouv.fr)",
        "intended_org": "French government entities",
        "description": "Restricted exclusively to verified French state ministries, departments, and official institutions.",
    },
    "gov.br": {
        "category": "Government",
        "name": "Brazilian Government (.gov.br)",
        "intended_org": "Brazilian government entities",
        "description": "Restricted exclusively to verified Brazilian federal, state, and municipal government bodies.",
    },
    "gov.cn": {
        "category": "Government",
        "name": "Chinese Government (.gov.cn)",
        "intended_org": "Chinese government entities",
        "description": "Restricted exclusively to authorized government organs of the People's Republic of China.",
    },
    "gov.sg": {
        "category": "Government",
        "name": "Singapore Government (.gov.sg)",
        "intended_org": "Singapore government entities",
        "description": "Restricted exclusively to verified public sector agencies and ministries of Singapore.",
    },
    "gov.za": {
        "category": "Government",
        "name": "South African Government (.gov.za)",
        "intended_org": "South African government entities",
        "description": "Restricted exclusively to verified South African government departments.",
    },

    # 2. International organisations and internet infrastructure
    "int": {
        "category": "International Organization",
        "name": "Intergovernmental Treaty Body (.int)",
        "intended_org": "Eligible intergovernmental organisations established under international treaties",
        "description": "Restricted strictly under IANA policy to treaty-based intergovernmental organizations, UN agencies, and sovereign entities.",
    },
    "arpa": {
        "category": "Internet Infrastructure",
        "name": "Address and Routing Parameter Area (.arpa)",
        "intended_org": "Internet infrastructure and technical DNS purposes",
        "description": "Core technical internet infrastructure zone managed exclusively by IANA and IETF for protocol and reverse-DNS parameters.",
    },

    # 3. Educational institutions
    "edu": {
        "category": "Education",
        "name": "US Higher Education (.edu)",
        "intended_org": "Eligible US postsecondary educational institutions",
        "description": "Restricted exclusively to accredited US postsecondary degree-granting institutions under Educause oversight.",
    },
    "ac.uk": {
        "category": "Education",
        "name": "UK Academic Institution (.ac.uk)",
        "intended_org": "Eligible UK academic institutions",
        "description": "Restricted exclusively to verified UK universities, colleges, and higher learning institutes via Jisc.",
    },
    "edu.in": {
        "category": "Education",
        "name": "Indian Educational Institution (.edu.in)",
        "intended_org": "Eligible Indian educational institutions",
        "description": "Restricted to recognized Indian schools, universities, and educational boards.",
    },
    "ac.in": {
        "category": "Education",
        "name": "Indian Academic Institution (.ac.in)",
        "intended_org": "Academic institutions (India)",
        "description": "Restricted to recognized Indian universities, colleges, and academic institutions.",
    },
    "edu.au": {
        "category": "Education",
        "name": "Australian Education (.edu.au)",
        "intended_org": "Eligible Australian educational institutions",
        "description": "Restricted exclusively to accredited Australian education and training organizations.",
    },
    "edu.sg": {
        "category": "Education",
        "name": "Singapore Education (.edu.sg)",
        "intended_org": "Eligible Singapore educational institutions",
        "description": "Restricted to recognized educational institutions registered with Singapore Ministry of Education.",
    },
    "ac.jp": {
        "category": "Education",
        "name": "Japanese Academic (.ac.jp)",
        "intended_org": "Eligible Japanese academic institutions",
        "description": "Restricted exclusively to Japanese higher education institutions, universities, and colleges under JPRS.",
    },
    "edu.cn": {
        "category": "Education",
        "name": "Chinese Education (.edu.cn)",
        "intended_org": "Eligible Chinese educational institutions",
        "description": "Restricted exclusively to accredited educational institutions under CERNET.",
    },

    # 4. Financial institutions and regulated industries
    "bank": {
        "category": "Financial Services",
        "name": "Verified Banking Institution (.bank)",
        "intended_org": "Verified banking institutions",
        "description": "Restricted exclusively to authenticated banks and retail banking institutions under strict fTLD identity verification and security requirements.",
    },
    "insurance": {
        "category": "Insurance",
        "name": "Verified Insurance Company (.insurance)",
        "intended_org": "Verified insurance companies and organisations",
        "description": "Restricted exclusively to authenticated insurance carriers and agencies under strict fTLD verification.",
    },
    "creditunion": {
        "category": "Financial Services",
        "name": "Credit Union (.creditunion)",
        "intended_org": "Eligible credit unions",
        "description": "Restricted exclusively to authenticated, chartered credit unions and associations.",
    },
    "cpa": {
        "category": "Regulated Professional",
        "name": "Certified Public Accountant (.cpa)",
        "intended_org": "Certified Public Accountants and eligible CPA firms",
        "description": "Restricted exclusively to licensed CPAs and accredited accounting firms via AICPA.",
    },
    "pharmacy": {
        "category": "Healthcare & Regulated",
        "name": "Verified Pharmacy (.pharmacy)",
        "intended_org": "Verified pharmacy-related organisations",
        "description": "Restricted exclusively to safe, verified pharmacies meeting National Association of Boards of Pharmacy (NABP) standards.",
    },
    "mutual": {
        "category": "Insurance & Mutuals",
        "name": "Mutual Organization (.mutual)",
        "intended_org": "Eligible mutual insurance organisations",
        "description": "Restricted to verified mutual insurance companies and societies.",
    },

    # 5. Professional and industry-specific organisations
    "aero": {
        "category": "Aviation",
        "name": "Aviation Industry (.aero)",
        "intended_org": "Aviation industry",
        "description": "Restricted exclusively to certified members of the global aviation community via SITA.",
    },
    "coop": {
        "category": "Cooperatives",
        "name": "Cooperative Organization (.coop)",
        "intended_org": "Eligible cooperatives",
        "description": "Restricted exclusively to verified cooperatives adhering to Rochdale Principles via DotCooperation.",
    },
    "museum": {
        "category": "Culture & Heritage",
        "name": "Museum Organization (.museum)",
        "intended_org": "Museums and qualifying museum-related organisations",
        "description": "Restricted exclusively to authenticated museums and cultural heritage institutions via ICOM.",
    },
    "post": {
        "category": "Postal & Logistics",
        "name": "Designated Postal Organization (.post)",
        "intended_org": "Designated postal organisations",
        "description": "Sponsored by the Universal Postal Union (UPU) exclusively for verified national postal operators.",
    },
    "cat": {
        "category": "Cultural Community",
        "name": "Catalan Linguistic Community (.cat)",
        "intended_org": "Catalan linguistic and cultural community",
        "description": "Community TLD managed by Fundacio puntCAT for certified Catalan cultural and linguistic presence.",
    },
    "jobs": {
        "category": "Employment",
        "name": "Employment & Hiring (.jobs)",
        "intended_org": "Employers and employment-related purposes",
        "description": "Restricted to authenticated corporate employers for recruitment and HR postings.",
    },
    "travel": {
        "category": "Travel Industry",
        "name": "Travel Industry (.travel)",
        "intended_org": "Travel industry-related registrations",
        "description": "Restricted to verified travel providers, tour operators, and tourism bureaus.",
    },
    "mobi": {
        "category": "Mobile Services",
        "name": "Mobile Services (.mobi)",
        "intended_org": "Mobile-related services and organisations",
        "description": "Dedicated namespace for verified mobile web and telecommunications services.",
    },
    "pro": {
        "category": "Certified Professional",
        "name": "Certified Professional (.pro)",
        "intended_org": "Certain professional registrations, depending on registry policy",
        "description": "Restricted to verified professionals and credentialed practitioners.",
    },

    # 6. Other verified or community-specific domains
    "eco": {
        "category": "Environmental",
        "name": "Environmental Community (.eco)",
        "intended_org": "Environmental and sustainability-related community",
        "description": "Restricted to organizations and individuals committed to validated environmental standards.",
    },
    "ngo": {
        "category": "Non-Governmental",
        "name": "Non-Governmental Organization (.ngo)",
        "intended_org": "Non-governmental organisations",
        "description": "Restricted exclusively to validated non-governmental organizations via Public Interest Registry.",
    },
    "ong": {
        "category": "Non-Governmental",
        "name": "Non-Governmental Organization (.ong)",
        "intended_org": "Non-governmental organisations",
        "description": "Restricted exclusively to validated non-governmental organizations via Public Interest Registry.",
    },
    "gal": {
        "category": "Cultural Community",
        "name": "Galician Community (.gal)",
        "intended_org": "Galician linguistic and cultural community",
        "description": "Restricted to the Galician language and cultural community.",
    },
    "eus": {
        "category": "Cultural Community",
        "name": "Basque Community (.eus)",
        "intended_org": "Basque linguistic and cultural community",
        "description": "Restricted to the Basque language and cultural community.",
    },
    "scot": {
        "category": "Regional Identity",
        "name": "Scottish Community (.scot)",
        "intended_org": "Scottish community",
        "description": "Dedicated community namespace for Scottish culture, business, and institutions.",
    },
    "wales": {
        "category": "Regional Identity",
        "name": "Welsh Community (.wales)",
        "intended_org": "Welsh community",
        "description": "Official community TLD for Wales.",
    },
    "cymru": {
        "category": "Regional Identity",
        "name": "Welsh Language (.cymru)",
        "intended_org": "Welsh community",
        "description": "Official community TLD for Wales in Welsh language.",
    },
    "paris": {
        "category": "Regional Identity",
        "name": "Paris City (.paris)",
        "intended_org": "Paris-related identity and presence",
        "description": "Official geographic TLD for the City of Paris.",
    },
    "london": {
        "category": "Regional Identity",
        "name": "London City (.london)",
        "intended_org": "London-related identity and presence",
        "description": "Official geographic TLD for London businesses and cultural institutions.",
    },

    # 7. India-specific restricted domain extensions
    "mil.in": {
        "category": "Military",
        "name": "Indian Military (.mil.in)",
        "intended_org": "Indian military",
        "description": "Restricted exclusively to Indian armed forces and Ministry of Defence organizations.",
    },
    "res.in": {
        "category": "Research",
        "name": "Indian Research Institution (.res.in)",
        "intended_org": "Research institutions",
        "description": "Restricted exclusively to recognized scientific and industrial research bodies in India (e.g. CSIR, DRDO, ISRO).",
    },
    "ernet.in": {
        "category": "Education & Research",
        "name": "Education and Research Network (.ernet.in)",
        "intended_org": "Educational and research networking",
        "description": "Official Indian National Educational and Research Network under MeitY.",
    },
    "bank.in": {
        "category": "Banking",
        "name": "Indian Banking Sector (.bank.in)",
        "intended_org": "Banking sector",
        "description": "Restricted exclusively to verified banks licensed under the Reserve Bank of India.",
    },
    "coop.in": {
        "category": "Cooperatives",
        "name": "Indian Cooperative Organization (.coop.in)",
        "intended_org": "Cooperative organisations",
        "description": "Restricted to registered cooperative societies and federations in India.",
    },
}

# Backward-compatibility alias
RESTRICTED_TLDS = RESTRICTED_DOMAINS_CATALOG

# Regex patterns for country-code and multi-level official suffixes worldwide
CC_OFFICIAL_PATTERNS = [
    # Government ccTLD patterns (.gov.*, .gob.*, .gouv.*, .gc.ca, .state.*)
    (
        re.compile(r"^(gov|gob|gouv|gc|fed|state)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Government",
        "Official Government Domain",
        "Verified national or regional government entities",
        "Restricted to verified national or regional government entities. Cannot be registered by the general public.",
    ),
    (
        re.compile(r"^[a-z0-9-]+\.(gov|gob|gouv)\.[a-z]{2,3}$", re.IGNORECASE),
        "Government",
        "Official Government Domain",
        "Verified government entities",
        "Restricted to verified government entities in relevant jurisdiction.",
    ),
    (
        re.compile(r"^nic\.[a-z]{2,3}$", re.IGNORECASE),
        "Government Infrastructure",
        "National Informatics Centre / Official Registry",
        "Government-related NIC infrastructure",
        "Restricted to official governmental informatics network.",
    ),
    # Military ccTLD patterns (.mil.*, .mod.*, .def.*)
    (
        re.compile(r"^(mil|mod|def)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Military",
        "Official Military / Armed Forces",
        "Military organisations",
        "Restricted exclusively to verified military and defense forces. Cannot be registered by the public.",
    ),
    # Educational ccTLD patterns (.edu.*, .ac.*)
    (
        re.compile(r"^(edu|ac)\.[a-z]{2,3}(\.[a-z]{2})?$", re.IGNORECASE),
        "Education",
        "Accredited Educational / Academic Institution",
        "Eligible academic and educational institutions",
        "Restricted exclusively to accredited universities, colleges, and academic institutions.",
    ),
]


def check_official_domain(hostname_or_url: str) -> Optional[OfficialDomainInfo]:
    """Check if a hostname or URL belongs to an official, restricted TLD that cannot be registered by the public.

    Args:
        hostname_or_url: Hostname (e.g. 'irs.gov', 'chase.bank', 'ox.ac.uk', 'isro.gov.in') or full URL.

    Returns:
        OfficialDomainInfo if matched, or None.
    """
    if not hostname_or_url or not isinstance(hostname_or_url, str):
        return None

    raw = hostname_or_url.strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip(".")

    if not raw:
        return None

    # 1. Exact or suffix match against RESTRICTED_DOMAINS_CATALOG
    for suffix, info in RESTRICTED_DOMAINS_CATALOG.items():
        if raw == suffix or raw.endswith("." + suffix):
            return OfficialDomainInfo(
                is_official=True,
                tld=suffix,
                category=info["category"],
                name=info["name"],
                intended_org=info["intended_org"],
                description=info["description"],
            )

    # 2. Check tldextract suffix
    extracted = tldextract.extract(raw)
    suffix = extracted.suffix.lower().strip(".")
    if suffix in RESTRICTED_DOMAINS_CATALOG:
        info = RESTRICTED_DOMAINS_CATALOG[suffix]
        return OfficialDomainInfo(
            is_official=True,
            tld=suffix,
            category=info["category"],
            name=info["name"],
            intended_org=info["intended_org"],
            description=info["description"],
        )

    # 3. Check multi-level regex patterns
    for pattern, cat, name, org, desc in CC_OFFICIAL_PATTERNS:
        if pattern.match(suffix):
            return OfficialDomainInfo(
                is_official=True,
                tld=suffix,
                category=cat,
                name=f"{name} (.{suffix})",
                intended_org=org,
                description=desc,
            )

    # 4. Check hostname split parts for custom regional patterns
    parts = raw.split(".")
    if len(parts) >= 2:
        last_two = f"{parts[-2]}.{parts[-1]}"
        for pattern, cat, name, org, desc in CC_OFFICIAL_PATTERNS:
            if pattern.match(last_two):
                return OfficialDomainInfo(
                    is_official=True,
                    tld=last_two,
                    category=cat,
                    name=f"{name} (.{last_two})",
                    intended_org=org,
                    description=desc,
                )

    return None


SEARCH_ENGINE_CATALOG: Dict[str, str] = {
    "google": "Google Search",
    "bing.com": "Microsoft Bing",
    "duckduckgo.com": "DuckDuckGo",
    "yahoo.com": "Yahoo Search",
    "brave.com": "Brave Search",
    "ecosia.org": "Ecosia",
    "startpage.com": "Startpage",
    "kagi.com": "Kagi",
    "yandex.com": "Yandex Search",
    "yandex.ru": "Yandex Search",
    "ya.ru": "Yandex Search",
    "baidu.com": "Baidu",
    "ask.com": "Ask.com",
    "wolframalpha.com": "WolframAlpha",
    "qwant.com": "Qwant",
}


def check_search_engine_query(url: str, canonical_url: str = "") -> Optional[Dict[str, Any]]:
    """Detect whether input is a browser keyword search or a query to a verified search engine.

    Returns:
        Dict metadata if verified as a search engine query, else None.
    """
    if not url or not isinstance(url, str):
        return None

    raw_input = url.strip()

    # 1. Detect raw keyword searches (e.g. phrases containing spaces without a valid protocol or domain)
    # e.g. "weather in new york", "best restaurants", "how to code python"
    if " " in raw_input and not raw_input.startswith(("http://", "https://")):
        return {
            "is_search": True,
            "name": "Browser Keyword Search",
            "type": "raw_keyword_query",
            "query": raw_input,
            "description": "User browser search keywords. Not a destination domain or phishing threat.",
        }

    # 2. Extract domain from canonical_url or url
    target = canonical_url or raw_input
    target_clean = target.lower()

    # Normalize protocol for parsing
    if "://" in target_clean:
        domain_part = target_clean.split("://", 1)[1]
    else:
        domain_part = target_clean

    hostname = domain_part.split("/")[0].split("?")[0].split(":")[0].strip()

    # Check search engine domains
    for se_domain, se_name in SEARCH_ENGINE_CATALOG.items():
        if se_domain == "google":
            if (
                hostname == "google.com"
                or hostname.endswith(".google.com")
                or hostname.startswith("google.")
                or ".google." in hostname
            ):
                return {
                    "is_search": True,
                    "name": se_name,
                    "domain": hostname,
                    "type": "search_engine_traffic",
                    "description": f"Verified official query to {se_name}. Legitimate search engine traffic.",
                }
        else:
            if hostname == se_domain or hostname.endswith(f".{se_domain}"):
                return {
                    "is_search": True,
                    "name": se_name,
                    "domain": hostname,
                    "type": "search_engine_traffic",
                    "description": f"Verified official query to {se_name}. Legitimate search engine traffic.",
                }

    # 3. Check common search URL paths with search query parameters (e.g. /search?q=..., /results?q=...)
    if "/search" in target_clean or "/results" in target_clean or "/?q=" in target_clean:
        if any(param in target_clean for param in ("?q=", "&q=", "?query=", "&query=", "?p=", "&p=", "?wd=", "&wd=")):
            return {
                "is_search": True,
                "name": "Search Engine Query",
                "domain": hostname,
                "type": "parameterized_search_query",
                "description": "Verified query to a search service. Search traffic is legitimate and safe.",
            }

    return None
