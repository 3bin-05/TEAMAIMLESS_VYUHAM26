import re
import json
from typing import Dict, Any, List, Optional

from local_ai.models import AIAnalysisResult, AIStatus
from local_ai.config import AIConfig
from local_ai.exceptions import AIParserError

VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "CRITICAL"}


def extract_json_str(raw_text: str) -> str:
    """Extract valid JSON substring from raw model output text, stripping any thinking/reasoning tags."""
    if not raw_text or not isinstance(raw_text, str):
        raise AIParserError("Raw model text is empty or non-string")

    text = raw_text.strip()
    # Strip <think>...</think> blocks if produced by reasoning models
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()

    # Match markdown code block ```json ... ```
    code_block_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text, re.IGNORECASE)
    if code_block_match:
        return code_block_match.group(1).strip()

    # Match outermost JSON object braces
    brace_match = re.search(r"(\{[\s\S]*\})", text)
    if brace_match:
        return brace_match.group(1).strip()

    return text


def parse_ai_response(
    raw_text: str,
    provider_name: str,
    model_name: str,
    latency_ms: float,
    config: Optional[AIConfig] = None,
) -> AIAnalysisResult:
    """Parse, validate, and sanitize raw LLM completion output into typed AIAnalysisResult.

    The LLM is now the final decision authority: its final_verdict and final_score
    are extracted and stored so the engine can apply them as the authoritative classification.
    """
    cfg = config or AIConfig()

    try:
        json_str = extract_json_str(raw_text)
        data = json.loads(json_str)

        if not isinstance(data, dict):
            raise AIParserError(f"Expected JSON object, got {type(data).__name__}")

        def sanitize_str(val: Any, max_len: int) -> str:
            if not val:
                return ""
            s = str(val).strip()
            return s[:max_len]

        def sanitize_list(val: Any, max_items: int, max_len: int) -> List[str]:
            if not isinstance(val, list):
                return []
            res: List[str] = []
            for item in val[:max_items]:
                if item:
                    res.append(str(item).strip()[:max_len])
            return res

        summary = sanitize_str(data.get("summary"), cfg.max_text_length)
        risk_assessment = sanitize_str(data.get("risk_assessment"), cfg.max_text_length)

        key_findings = sanitize_list(data.get("key_findings"), cfg.max_findings, cfg.max_text_length)
        supporting_signals = sanitize_list(data.get("supporting_signals"), cfg.max_findings, cfg.max_text_length)
        conflicting_signals = sanitize_list(data.get("conflicting_signals"), cfg.max_findings, cfg.max_text_length)
        uncertainties = sanitize_list(data.get("uncertainties"), cfg.max_findings, cfg.max_text_length)

        # --- Extract LLM-authoritative final verdict and score ---
        raw_verdict = data.get("final_verdict")
        final_verdict: Optional[str] = None
        if isinstance(raw_verdict, str) and raw_verdict.strip().upper() in VALID_VERDICTS:
            final_verdict = raw_verdict.strip().upper()

        raw_score = data.get("final_score")
        final_score: Optional[int] = None
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
            final_score = max(0, min(100, int(round(raw_score))))

        # Consistency check: clamp score to match verdict ranges
        if final_verdict and final_score is not None:
            if final_verdict == "SAFE" and final_score > 29:
                final_score = min(29, final_score)
            elif final_verdict == "SUSPICIOUS" and not (30 <= final_score <= 79):
                final_score = max(30, min(79, final_score))
            elif final_verdict == "CRITICAL" and final_score < 80:
                final_score = max(80, final_score)

        return AIAnalysisResult(
            available=True,
            status=AIStatus.SUCCESS,
            provider=provider_name,
            model=model_name,
            summary=summary,
            risk_assessment=risk_assessment,
            key_findings=key_findings,
            supporting_signals=supporting_signals,
            conflicting_signals=conflicting_signals,
            uncertainties=uncertainties,
            final_verdict=final_verdict,
            final_score=final_score,
            latency_ms=round(latency_ms, 2),
            error=None,
        )

    except Exception as e:
        return AIAnalysisResult(
            available=False,
            status=AIStatus.INVALID_RESPONSE,
            provider=provider_name,
            model=model_name,
            latency_ms=round(latency_ms, 2),
            error=f"Failed to parse AI response JSON: {str(e)}",
        )
