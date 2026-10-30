import json
import logging
import re
import time
import httpx

from app.core.config import settings
from app.services.ai.ai_interface import AIProvider
from app.services.ai.ai_schemas import AIEvidenceInput, AIAnalysisResult, AIStructuredAnalysis
from app.services.ai.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt
from app.services.ai.runtime_detector import OllamaRuntimeDetector

logger = logging.getLogger("aegis")


def _clean_json_text(raw_text: str) -> str:
    """Strips markdown code blocks, think blocks, and extraneous whitespace from LLM output."""
    text = str(raw_text).strip()
    # Strip <think>...</think> tags if model outputs thought tokens
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Strip ```json ... ``` code fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


class LocalOllamaProvider(AIProvider):
    """
    Local AI Provider executing inference on Ollama HTTP daemon.
    Guarantees that all URL and threat intelligence data remains strictly on-device.
    """

    def __init__(
        self,
        detector: OllamaRuntimeDetector | None = None,
        base_url: str | None = None,
        timeout: float | None = None
    ):
        self.detector = detector or OllamaRuntimeDetector(base_url=base_url)
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.timeout = timeout or max(35.0, float(settings.AEGIS_AI_TIMEOUT_SECONDS))

    @property
    def provider_name(self) -> str:
        return "local_ollama"

    @property
    def model_name(self) -> str:
        selected = self.detector.selected_model
        if isinstance(selected, str) and selected.strip():
            return selected.strip()
        if settings.OLLAMA_MODEL.strip():
            return settings.OLLAMA_MODEL.strip()
        return "none"

    @property
    def is_cloud(self) -> bool:
        return False

    @property
    def is_available(self) -> bool:
        return self.detector.is_available

    async def check_availability(self) -> bool:
        """Verifies local Ollama daemon and model inference status."""
        return await self.detector.detect()

    async def analyze(self, evidence: AIEvidenceInput) -> AIAnalysisResult:
        """
        Executes structured threat analysis locally using Ollama.
        Forces JSON output format and validates with Pydantic AIStructuredAnalysis schema.
        """
        # Ensure model is available
        is_avail = await self.check_availability()
        if not is_avail:
            return AIAnalysisResult(
                status="unavailable",
                provider=self.provider_name,
                model=self.model_name,
                is_cloud=False,
                error_reason=self.detector.last_error or "Local Ollama model unavailable"
            )

        active_model = self.model_name
        prompt = build_analysis_prompt(evidence)

        payload = {
            "model": active_model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {
                "num_predict": 512,
                "temperature": 0.1,  # Low temperature for deterministic analysis
                "top_p": 0.9
            }
        }

        generate_url = f"{self.base_url}/api/generate"
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(generate_url, json=payload)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if response.status_code != 200:
                    err_msg = f"Ollama HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(err_msg)
                    return AIAnalysisResult(
                        status="failed",
                        provider=self.provider_name,
                        model=active_model,
                        is_cloud=False,
                        latency_ms=latency_ms,
                        error_reason=err_msg
                    )

                resp_data = response.json()
                raw_output = resp_data.get("response", "")

            # Parse and validate JSON
            cleaned_json = _clean_json_text(raw_output)
            try:
                parsed_dict = json.loads(cleaned_json)
                if isinstance(parsed_dict, dict):
                    # Normalize risk_level
                    rl = str(parsed_dict.get("risk_level", "")).lower().strip()
                    if rl in ("safe", "legitimate", "clean", "benign", "low"):
                        parsed_dict["risk_level"] = "safe"
                    elif rl in ("malicious", "critical", "phishing", "danger", "high"):
                        parsed_dict["risk_level"] = "malicious"
                    elif rl in ("suspicious", "suspicion", "medium", "warn"):
                        parsed_dict["risk_level"] = "suspicious"
                    elif rl not in ("safe", "suspicious", "malicious", "inconclusive"):
                        parsed_dict["risk_level"] = "inconclusive"

                    # Normalize recommendation
                    rec = str(parsed_dict.get("recommendation", "")).lower().strip()
                    if rec in ("allow", "safe", "proceed"):
                        parsed_dict["recommendation"] = "allow"
                    elif rec in ("block", "cancel", "deny"):
                        parsed_dict["recommendation"] = "block"
                    elif rec in ("warn", "caution", "proceed_with_caution"):
                        parsed_dict["recommendation"] = "warn"
                    elif rec not in ("allow", "warn", "block", "inconclusive"):
                        parsed_dict["recommendation"] = "inconclusive"

                    # Normalize summary if missing
                    if not parsed_dict.get("summary"):
                        parsed_dict["summary"] = parsed_dict.get("explanation") or f"Analysis concluded with risk level {parsed_dict['risk_level']}."

                structured = AIStructuredAnalysis.model_validate(parsed_dict)

                return AIAnalysisResult(
                    status="completed",
                    provider=self.provider_name,
                    model=active_model,
                    is_cloud=False,
                    latency_ms=latency_ms,
                    analysis=structured,
                    raw_explanation=structured.summary
                )
            except (json.JSONDecodeError, Exception) as val_err:
                logger.warning(f"Ollama output validation error: {val_err} | Raw: {raw_output[:200]}")
                return AIAnalysisResult(
                    status="failed",
                    provider=self.provider_name,
                    model=active_model,
                    is_cloud=False,
                    latency_ms=latency_ms,
                    raw_explanation=raw_output[:500] if raw_output else None,
                    error_reason=f"Structured JSON validation failed: {val_err}"
                )

        except httpx.TimeoutException:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Local Ollama inference timed out after {self.timeout}s")
            return AIAnalysisResult(
                status="failed",
                provider=self.provider_name,
                model=active_model,
                is_cloud=False,
                latency_ms=latency_ms,
                error_reason=f"Local AI inference timed out after {self.timeout}s"
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Local Ollama inference exception: {exc}")
            return AIAnalysisResult(
                status="failed",
                provider=self.provider_name,
                model=active_model,
                is_cloud=False,
                latency_ms=latency_ms,
                error_reason=f"Local AI inference error: {exc}"
            )
