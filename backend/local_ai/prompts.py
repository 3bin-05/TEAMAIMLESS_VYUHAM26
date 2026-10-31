import json
from typing import Dict, Any, List

from local_ai.models import AIContext

SYSTEM_PROMPT = """You are the AEGIS Cybersecurity Intelligence Engine — the authoritative final decision arbiter for URL threat classification.

You receive structured security telemetry gathered by Aegis's multi-module pipeline:
1. Lexical ML Model trained on URL phishing datasets
2. Threat Intelligence APIs (VirusTotal, Google Safe Browsing)
3. Live RDAP Domain Scraper (registration age, registrar, privacy status)
4. Web History & AEO Footprint (internet presence, brand authority, historical reputation)
5. Live Infrastructure Probers (DNS resolution, SSL/TLS certificates, redirects)

YOUR MANDATE — STRICTLY THREE OUTPUT STATES:
Every classification decision MUST be categorized into exactly one of three states (no other states exist):
1. "SAFE" (Score 0-29): Low phishing risk. Established legitimate entity, verified authentic web history, or clean benign service.
2. "SUSPICIOUS" (Score 30-69): Elevated or ambiguous risk. Unverified/new domain with zero web footprint, anomalous redirects, or missing verifiable identity.
3. "MALICIOUS" (Score 70-100): High risk threat. Active phishing, brand impersonation/typosquatting, deceptive lookalike domain, or confirmed threat intel hit.

CORE DECISION RULES:

1. AEO & WEB HISTORY IS A MAJOR FACTOR:
   - Established global platforms (e.g. instagram.com, facebook.com, meta.com, google.com, apple.com, microsoft.com, amazon.com, openai.com, chase.com, paypal.com, github.com) have massive, verified multi-decade web histories and search authority.
   - When a domain is a verified authentic entity with major web history, it is SAFE unless compromised by malicious redirects or verified threat intel.

2. WHOIS / RDAP PRIVACY REDACTION RULE (CRITICAL):
   - Major legitimate corporations (like Instagram, Meta, Google, Microsoft, Cloudflare) routinely redact or hide registrant details in public RDAP/WHOIS records for corporate privacy and anti-scraping defense.
   - REDACTED, HIDDEN, OR MISSING RDAP REGISTRANT DETAILS ON AN ESTABLISHED BRAND DOMAIN MUST NEVER BE TREATED AS A PHISHING INDICATOR.
   - Do NOT penalize established domains for privacy-redacted RDAP records.

3. MULTI-MODULE RESILIENCE & FALLBACK:
   - If any module fails to produce data (for example, if VirusTotal hits a 429 rate limit or RDAP age is unlisted), NEVER fail the evaluation.
   - Evaluate the URL using all available remaining modules (ML findings, Web History/AEO footprint, DNS/TLS status, brand lookalike checks).

4. BRAND LOOKALIKE & DECEPTIVE REPLICAS (TYPOSQUATTING):
   - If a domain mimics a known brand (e.g. 'facelook.com', 'paypa1.com', 'chase-security-login.com') with character swaps, added security stems, or zero authentic web history:
   - This is active impersonation → minimum verdict: SUSPICIOUS (score ≥ 55), or MALICIOUS (score ≥ 75).

OUTPUT FORMAT:
Output MUST be a single valid JSON object with NO markdown preamble or prose outside the JSON:

{
  "final_verdict": "SAFE | SUSPICIOUS | MALICIOUS",
  "final_score": <integer 0-100>,
  "summary": "1-2 sentence evidence-backed overview explaining why this verdict was reached.",
  "risk_assessment": "Comprehensive analysis of ML findings, Web History/AEO footprint, RDAP details, and threat intelligence.",
  "key_findings": ["Specific observations synthesizing ML, RDAP, Web History, and Threat Intel"],
  "supporting_signals": ["Signals supporting this final verdict"],
  "conflicting_signals": ["Mitigating or conflicting signals observed (e.g. hidden RDAP is legitimate for major brands)"],
  "uncertainties": ["Any modules that were unavailable or rate-limited"]
}"""


def build_ai_context(analysis_result: Any) -> AIContext:
    """Extract a safe, controlled AIContext dictionary from an AnalysisResult instance."""
    url = getattr(analysis_result, "url", "")
    risk_score = getattr(analysis_result, "risk_score", 0)
    classification = getattr(analysis_result, "classification", "SAFE")
    # Normalize legacy CRITICAL to MALICIOUS
    if classification == "CRITICAL":
        classification = "MALICIOUS"
    reasons = getattr(analysis_result, "reasons", [])
    raw_signals = getattr(analysis_result, "signals", {}) or {}

    ml_signal = {
        "probability": raw_signals.get("ml_probability"),
        "prediction": raw_signals.get("ml_prediction"),
        "label": raw_signals.get("ml_label"),
    }

    cyber = raw_signals.get("cyber_analysis", {}) or {}

    dns_signals = {
        "resolved": cyber.get("dns", {}).get("data", {}).get("resolved"),
        "a_records": cyber.get("dns", {}).get("data", {}).get("a_records", []),
        "is_direct_ip": cyber.get("dns", {}).get("data", {}).get("is_direct_ip"),
    }

    http_signals = {
        "status_code": cyber.get("http", {}).get("data", {}).get("status_code"),
        "content_type": cyber.get("http", {}).get("data", {}).get("content_type"),
        "scheme": cyber.get("http", {}).get("data", {}).get("scheme"),
    }

    tls_signals = {
        "available": cyber.get("tls", {}).get("available"),
        "tls_version": cyber.get("tls", {}).get("data", {}).get("tls_version"),
        "hostname_verified": cyber.get("tls", {}).get("data", {}).get("hostname_verified"),
        "days_until_expiry": cyber.get("tls", {}).get("data", {}).get("certificate", {}).get("days_until_expiry"),
    }

    redirect_signals = {
        "redirect_count": cyber.get("redirects", {}).get("data", {}).get("redirect_count", 0),
        "hostname_changes": cyber.get("redirects", {}).get("data", {}).get("hostname_changes", 0),
        "scheme_changes": cyber.get("redirects", {}).get("data", {}).get("scheme_changes", 0),
    }

    threat_intel_data = cyber.get("threat_intel", {}).get("data", {}) or {}
    threat_intel_signals = {
        "matched": threat_intel_data.get("matched", False),
        "is_blocked": threat_intel_data.get("is_blocked", False),
        "is_allowlisted": threat_intel_data.get("is_allowlisted", False),
        "is_official_domain": threat_intel_data.get("is_official_domain", False),
        "official_info": threat_intel_data.get("official_info"),
        "virustotal": threat_intel_data.get("virustotal", {}),
        "safe_browsing": threat_intel_data.get("safe_browsing", {}),
        "brand_lookalike": threat_intel_data.get("brand_lookalike"),
    }

    rdap_signals = cyber.get("rdap", {}).get("data", {}) or {}
    web_history_signals = cyber.get("web_history", {}).get("data", {}) or {}

    return AIContext(
        url=url,
        ml_signal=ml_signal,
        risk_score=risk_score,
        classification=classification,
        dns_signals=dns_signals,
        http_signals=http_signals,
        tls_signals=tls_signals,
        redirect_signals=redirect_signals,
        threat_intel_signals=threat_intel_signals,
        rdap_signals=rdap_signals,
        web_history_signals=web_history_signals,
        reasons=list(reasons),
    )


def build_prompt_messages(context: AIContext) -> List[Dict[str, str]]:
    """Construct standard system and user chat messages for LLM request."""
    user_payload = {
        "target_url": context.url,
        "preliminary_assessment": {
            "risk_score": context.risk_score,
            "classification": context.classification,
        },
        "evidence_signals": {
            "ml_model_findings": context.ml_signal,
            "web_history_and_aeo_presence": context.web_history_signals,
            "rdap_domain_registration": context.rdap_signals,
            "threat_intelligence_feeds": context.threat_intel_signals,
            "infrastructure_tls_dns": {
                "dns": context.dns_signals,
                "tls": context.tls_signals,
                "http": context.http_signals,
                "redirects": context.redirect_signals,
            },
        },
        "pipeline_reasons": context.reasons,
    }

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Analyze the following security telemetry and output your definitive JSON verdict "
                "strictly as 'SAFE', 'SUSPICIOUS', or 'MALICIOUS':\n\n"
                f"{json.dumps(user_payload, indent=2)}"
            ),
        },
    ]


CLAUDE_OPTIMIZED_SYSTEM_PROMPT = """You are AEGIS Cyber Intelligence — the final decision arbiter for URL threat classification.
Output strictly 1 of 3 verdicts in compact JSON:
- "SAFE" (Score 0-29): Low phishing risk, established authentic web history, clean service.
- "SUSPICIOUS" (Score 30-69): Elevated or ambiguous risk, unverified/new domain with zero footprint, or anomalous redirects.
- "MALICIOUS" (Score 70-100): High risk threat, active phishing, brand impersonation/typosquatting, or threat intel hit.

CORE RULES:
1. Major brands (Meta, Google, Apple, etc.) often redact WHOIS/RDAP details. Redacted WHOIS on established domains is NEVER phishing.
2. AEO & Web History: Major established entities are SAFE unless compromised or confirmed malicious.
3. Resilient fallback: If any feed (e.g. VirusTotal 429) is missing, evaluate using remaining signals.
4. Typosquatting/brand lookalike on unknown domains is SUSPICIOUS (≥55) or MALICIOUS (≥75).

JSON FORMAT ONLY (no markdown fences or prose):
{"final_verdict":"SAFE|SUSPICIOUS|MALICIOUS","final_score":<0-100>,"summary":"1-2 concise sentences","key_findings":["f1","f2"],"uncertainties":[]}"""


def build_claude_optimized_messages(context: AIContext) -> List[Dict[str, str]]:
    """Construct ultra-compact, token-efficient messages for Claude to minimize latency and token usage."""
    telemetry: Dict[str, Any] = {
        "url": context.url,
        "preliminary": f"{context.classification} (score: {context.risk_score})",
    }
    if context.ml_signal:
        prob = context.ml_signal.get("probability")
        if prob is not None:
            telemetry["ml_prob"] = round(float(prob), 4)

    if context.web_history_signals and context.web_history_signals.get("has_major_web_history"):
        telemetry["web_history"] = {
            "entity": context.web_history_signals.get("entity_name"),
            "authority": context.web_history_signals.get("web_authority"),
        }

    if context.rdap_signals:
        rdap_age = context.rdap_signals.get("domain_age_days")
        rdap_privacy = context.rdap_signals.get("privacy_redacted")
        if rdap_age is not None or rdap_privacy is not None:
            telemetry["rdap"] = {
                "age_days": rdap_age,
                "privacy_redacted": rdap_privacy,
            }

    ti = context.threat_intel_signals
    if ti:
        if ti.get("brand_lookalike"):
            telemetry["brand_lookalike"] = ti.get("brand_lookalike")
        if ti.get("is_allowlisted"):
            telemetry["allowlisted"] = True
        vt = ti.get("virustotal", {})
        if vt and vt.get("available") and vt.get("malicious", 0) > 0:
            telemetry["vt_malicious"] = vt.get("malicious")
        sb = ti.get("safe_browsing", {})
        if sb and sb.get("is_threat"):
            telemetry["safe_browsing"] = sb.get("threat_types", [])

    return [
        {"role": "system", "content": CLAUDE_OPTIMIZED_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"URL Telemetry:\n{json.dumps(telemetry, separators=(',', ':'))}\nEvaluate:",
        },
    ]
