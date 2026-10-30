from datetime import datetime, timezone
import logging
from typing import Literal

from app.core.config import settings
from app.services.ai.ai_interface import AIProvider
from app.services.ai.ai_schemas import (
    AIEvidenceInput,
    AIAnalysisResult,
    AIStatusResponse
)
from app.services.ai.cloud_llm import ClaudeCloudProvider
from app.services.ai.local_llm import LocalOllamaProvider
from app.services.ai.runtime_detector import OllamaRuntimeDetector

logger = logging.getLogger("aegis")

AIMode = Literal["AUTO", "LOCAL_ONLY", "CLOUD_ONLY", "DISABLED"]


class HybridAIRouter:
    """
    Intelligent Hybrid AI Router for AEGIS:
    - Coordinates between Local Ollama and Cloud Claude providers.
    - Strictly enforces user privacy and cloud consent policy.
    - Implements circuit-breaking/cooldown on provider errors.
    - Provides deterministic fallback: Local -> Cloud (if consented) -> Non-blocking continuation.
    """

    def __init__(
        self,
        local_provider: LocalOllamaProvider | None = None,
        cloud_provider: ClaudeCloudProvider | None = None,
        detector: OllamaRuntimeDetector | None = None,
        mode: str | None = None,
        cooldown_seconds: float = 60.0
    ):
        self.detector = detector or OllamaRuntimeDetector()
        self.local = local_provider or LocalOllamaProvider(detector=self.detector)
        self.cloud = cloud_provider or ClaudeCloudProvider()
        self.mode: str = (mode or settings.AEGIS_AI_MODE).upper()
        self.cooldown_seconds = cooldown_seconds

        # Circuit breaker cooldown tracking
        self._local_failure_cooldown_until: datetime | None = None
        self._cloud_failure_cooldown_until: datetime | None = None

    def _is_local_in_cooldown(self) -> bool:
        if self._local_failure_cooldown_until is None:
            return False
        return datetime.now(timezone.utc) < self._local_failure_cooldown_until

    def _is_cloud_in_cooldown(self) -> bool:
        if self._cloud_failure_cooldown_until is None:
            return False
        return datetime.now(timezone.utc) < self._cloud_failure_cooldown_until

    def _mark_local_failure(self):
        self._local_failure_cooldown_until = datetime.now(timezone.utc).fromtimestamp(
            datetime.now(timezone.utc).timestamp() + self.cooldown_seconds,
            tz=timezone.utc
        )

    def _mark_cloud_failure(self):
        self._cloud_failure_cooldown_until = datetime.now(timezone.utc).fromtimestamp(
            datetime.now(timezone.utc).timestamp() + self.cooldown_seconds,
            tz=timezone.utc
        )

    def is_cloud_permitted(self, request_consent: bool | None = None) -> bool:
        """
        Evaluates whether cloud processing is permitted for this request:
        Requires BOTH conditions:
        1. Backend cloud AI is enabled in configuration (settings.AEGIS_CLOUD_AI_ENABLED is True).
        2. The individual request explicitly grants cloud processing permission (request_consent is True).
        Plus a configured Anthropic API key.
        If either condition is False or absent, cloud processing is strictly forbidden.
        """
        if not settings.AEGIS_CLOUD_AI_ENABLED:
            return False

        if request_consent is not True:
            return False

        return bool(settings.ANTHROPIC_API_KEY and settings.ANTHROPIC_API_KEY.strip())

    async def get_status(self) -> AIStatusResponse:
        """Generates comprehensive status report for GET /api/v1/ai/status."""
        await self.detector.detect()

        local_ready = self.detector.is_available and not self._is_local_in_cooldown()
        cloud_ready = bool(settings.ANTHROPIC_API_KEY and settings.ANTHROPIC_API_KEY.strip())
        cloud_permitted = settings.AEGIS_CLOUD_AI_ENABLED and cloud_ready

        # Determine preferred provider under active configuration
        if self.mode == "DISABLED":
            preferred = "none (disabled)"
        elif self.mode == "LOCAL_ONLY":
            preferred = "local_ollama" if local_ready else "none (local unavailable)"
        elif self.mode == "CLOUD_ONLY":
            preferred = "cloud_claude" if cloud_permitted else "none (cloud not permitted/configured)"
        elif self.mode == "AUTO":
            if local_ready:
                preferred = "local_ollama"
            elif cloud_permitted:
                preferred = "cloud_claude"
            else:
                preferred = "none (no provider available)"
        else:
            preferred = "unknown"

        return AIStatusResponse(
            mode=self.mode,
            ollama_available=self.detector.is_available,
            ollama_reachable=self.detector.is_reachable,
            ollama_models_found=self.detector.models_found,
            ollama_selected_model=self.detector.selected_model,
            ollama_inference_verified=self.detector.inference_verified,
            cloud_ai_configured=cloud_ready,
            cloud_ai_enabled=settings.AEGIS_CLOUD_AI_ENABLED,
            cloud_model=settings.ANTHROPIC_MODEL,
            preferred_provider=preferred,
            last_health_check=self.detector.last_checked
        )

    async def analyze(
        self,
        evidence: AIEvidenceInput,
        allow_cloud_ai: bool | None = None
    ) -> AIAnalysisResult:
        """
        Main entry point for hybrid AI threat analysis:
        - Evaluates routing mode (AUTO, LOCAL_ONLY, CLOUD_ONLY, DISABLED).
        - Dispatches to Local Ollama or Cloud Claude according to consent & availability.
        - Provides automatic cloud fallback if permitted and local fails.
        """
        if self.mode == "DISABLED":
            logger.info("AI analysis skipped: mode is DISABLED.")
            return AIAnalysisResult(
                status="disabled",
                provider="none",
                model="none",
                is_cloud=False,
                error_reason="AI intelligence engine is DISABLED by configuration"
            )

        cloud_allowed = self.is_cloud_permitted(request_consent=allow_cloud_ai)

        # -------------------------------------------------------------
        # Mode: LOCAL_ONLY
        # -------------------------------------------------------------
        if self.mode == "LOCAL_ONLY":
            if self._is_local_in_cooldown():
                return AIAnalysisResult(
                    status="unavailable",
                    provider="local_ollama",
                    model=self.local.model_name,
                    is_cloud=False,
                    error_reason="Local AI provider is in cooldown following a previous error"
                )

            res = await self.local.analyze(evidence)
            if res.status != "completed":
                self._mark_local_failure()
            return res

        # -------------------------------------------------------------
        # Mode: CLOUD_ONLY
        # -------------------------------------------------------------
        if self.mode == "CLOUD_ONLY":
            if not cloud_allowed:
                return AIAnalysisResult(
                    status="unavailable",
                    provider="cloud_claude",
                    model=self.cloud.model_name,
                    is_cloud=True,
                    error_reason="Cloud AI processing is disabled or user consent was not granted"
                )

            if self._is_cloud_in_cooldown():
                return AIAnalysisResult(
                    status="unavailable",
                    provider="cloud_claude",
                    model=self.cloud.model_name,
                    is_cloud=True,
                    error_reason="Cloud AI provider is in cooldown following a previous error"
                )

            res = await self.cloud.analyze(evidence)
            if res.status != "completed":
                self._mark_cloud_failure()
            return res

        # -------------------------------------------------------------
        # Mode: AUTO (Default)
        # -------------------------------------------------------------
        # 1. Attempt Local AI first if available and not in cooldown
        local_available = await self.local.check_availability()

        if local_available and not self._is_local_in_cooldown():
            logger.info("Hybrid router: selecting Local Ollama provider.")
            local_res = await self.local.analyze(evidence)

            if local_res.status == "completed":
                return local_res

            # Local failed during execution
            logger.warning(f"Local Ollama inference failed: {local_res.error_reason}")
            self._mark_local_failure()

            # Attempt cloud fallback ONLY if cloud consent is granted
            if cloud_allowed and not self._is_cloud_in_cooldown():
                logger.info("Hybrid router: local failed, attempting permitted Cloud Claude fallback.")
                cloud_res = await self.cloud.analyze(evidence)
                if cloud_res.status == "completed":
                    return cloud_res
                else:
                    self._mark_cloud_failure()

            return local_res

        # 2. Local unavailable: use Cloud if permitted
        if cloud_allowed and not self._is_cloud_in_cooldown():
            logger.info("Hybrid router: local unavailable, routing to permitted Cloud Claude provider.")
            cloud_res = await self.cloud.analyze(evidence)
            if cloud_res.status != "completed":
                self._mark_cloud_failure()
            return cloud_res

        # 3. Neither provider available or permitted
        reason = "No AI provider available (Local Ollama unavailable and Cloud processing not enabled/configured)"
        logger.info(f"Hybrid router: {reason}")
        return AIAnalysisResult(
            status="unavailable",
            provider="none",
            model="none",
            is_cloud=False,
            error_reason=reason
        )


# Singleton router instance for application lifecycle
router = HybridAIRouter()
