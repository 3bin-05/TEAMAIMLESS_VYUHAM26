import json
import logging
import time
from app.core.config import settings
from app.services.ai.ai_interface import AIProvider
from app.services.ai.ai_schemas import AIEvidenceInput, AIAnalysisResult, AIStructuredAnalysis
from app.services.ai.local_llm import _clean_json_text
from app.services.ai.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt

logger = logging.getLogger("aegis")


class ClaudeCloudProvider(AIProvider):
    """
    Cloud AI Provider executing analysis via Anthropic Claude API.
    Used as an intelligent fallback or cloud-preferred provider only when
    explicit user consent and API credentials are provided.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None
    ):
        self.api_key = api_key or settings.ANTHROPIC_API_KEY
        self.model = model or settings.ANTHROPIC_MODEL or "claude-3-5-haiku-20241022"
        self.timeout = timeout or float(settings.AEGIS_AI_TIMEOUT_SECONDS)

    @property
    def provider_name(self) -> str:
        return "cloud_claude"

    @property
    def model_name(self) -> str:
        return self.model

    @property
    def is_cloud(self) -> bool:
        return True

    @property
    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    async def check_availability(self) -> bool:
        """Checks whether the cloud provider is configured with credentials."""
        return self.is_available

    async def analyze(self, evidence: AIEvidenceInput) -> AIAnalysisResult:
        """
        Executes cloud inference using Anthropic Claude API.
        Validates returned JSON against AIStructuredAnalysis schema.
        """
        if not self.api_key or not self.api_key.strip():
            return AIAnalysisResult(
                status="unavailable",
                provider=self.provider_name,
                model=self.model_name,
                is_cloud=True,
                error_reason="Anthropic API key not configured"
            )

        prompt = build_analysis_prompt(evidence)
        start_time = time.perf_counter()

        try:
            import anthropic

            client = anthropic.AsyncAnthropic(
                api_key=self.api_key,
                timeout=self.timeout
            )

            response = await client.messages.create(
                model=self.model_name,
                max_tokens=600,
                temperature=0.1,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

            raw_text = ""
            for block in response.content:
                if block.type == "text":
                    raw_text += block.text

            cleaned_json = _clean_json_text(raw_text)
            parsed_dict = json.loads(cleaned_json)
            if isinstance(parsed_dict, dict):
                parsed_dict = AIStructuredAnalysis.from_legacy_data(parsed_dict)
            structured = AIStructuredAnalysis.model_validate(parsed_dict)

            return AIAnalysisResult(
                status="completed",
                provider=self.provider_name,
                model=self.model_name,
                is_cloud=True,
                latency_ms=latency_ms,
                analysis=structured,
                raw_explanation=structured.explanation
            )

        except json.JSONDecodeError as json_err:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Claude cloud AI response was not valid JSON: {json_err}")
            return AIAnalysisResult(
                status="failed",
                provider=self.provider_name,
                model=self.model_name,
                is_cloud=True,
                latency_ms=latency_ms,
                error_reason=f"Structured JSON parsing error: {json_err}"
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            exc_name = type(exc).__name__

            if "AuthenticationError" in exc_name:
                err_msg = "Claude API authentication failed (invalid API key)"
            elif "RateLimitError" in exc_name:
                err_msg = "Claude API rate limit exceeded (HTTP 429)"
            elif "APITimeoutError" in exc_name:
                err_msg = f"Claude API request timed out after {self.timeout}s"
            elif "APIConnectionError" in exc_name:
                err_msg = "Unable to connect to Claude API servers"
            else:
                err_msg = f"Claude API error: {exc}"

            logger.warning(f"Cloud AI inference failed: {err_msg}")
            return AIAnalysisResult(
                status="failed",
                provider=self.provider_name,
                model=self.model_name,
                is_cloud=True,
                latency_ms=latency_ms,
                error_reason=err_msg
            )
