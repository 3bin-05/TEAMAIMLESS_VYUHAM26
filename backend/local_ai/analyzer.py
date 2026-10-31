import time
import logging
from typing import Optional, Any

from local_ai.config import AIConfig
from local_ai.models import AIAnalysisResult, AIStatus
from local_ai.exceptions import (
    AIError,
    AIProviderError,
    AITimeoutError,
    AIModelNotFoundError,
    AIDisabledError,
)
from local_ai.providers import LocalAIProvider, OllamaProvider, ClaudeProvider
from local_ai.prompts import (
    build_ai_context,
    build_prompt_messages,
    build_claude_optimized_messages,
)
from local_ai.parser import parse_ai_response

logger = logging.getLogger("aegis.ai")


class LocalAIAnalyzer:
    """Hybrid AI coordinator prioritizing local LLM execution with resilient Claude API fallback."""

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        provider: Optional[LocalAIProvider] = None,
    ):
        self.config = config or AIConfig()
        self.mode = self.config.provider.lower()

        # Initialize primary and fallback providers
        if provider is not None:
            self.provider = provider
            self.local_provider = provider
            self.claude_provider: Optional[ClaudeProvider] = None
        else:
            self.local_provider = OllamaProvider(
                base_url=self.config.base_url,
                default_model=self.config.model,
            )
            self.claude_provider = ClaudeProvider(
                api_key=self.config.anthropic_api_key,
                default_model=self.config.claude_model,
            )
            self.provider = self.local_provider

    def analyze(self, analysis_result: Any) -> AIAnalysisResult:
        """Analyze security telemetry using Hybrid Architecture.

        Execution Order (in hybrid mode):
          1. 1st Priority: Local LLM (Ollama)
          2. Fallback: Cloud LLM (Claude 3.5 Haiku with token-optimized prompt)
          3. Graceful fallback on network/quota errors

        Args:
            analysis_result: An Aegis AnalysisResult instance containing security evidence.

        Returns:
            AIAnalysisResult with authoritative verdict, score, summary, and findings.
        """
        if not self.config.enabled:
            return AIAnalysisResult(
                available=False,
                status=AIStatus.DISABLED,
                provider="disabled",
                model="none",
            )

        start_time = time.perf_counter()

        # Build context
        try:
            context = build_ai_context(analysis_result)
        except Exception as e:
            return AIAnalysisResult(
                available=False,
                status=AIStatus.PROVIDER_ERROR,
                provider="hybrid",
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Failed to construct AI context: {str(e)}",
            )

        # Direct Claude mode
        if self.mode == "claude":
            return self._run_claude(context, start_time)

        # Direct Ollama mode
        if self.mode == "ollama":
            return self._run_local(context, start_time)

        # Hybrid Mode: 1st Priority Local LLM -> Fallback Claude API
        local_healthy = self.local_provider.health_check()
        model_installed = local_healthy and self.local_provider.is_model_available(self.config.model)

        if local_healthy and model_installed:
            try:
                local_res = self._run_local(context, start_time)
                if local_res.available and local_res.status == AIStatus.SUCCESS:
                    return local_res
                logger.warning("Local LLM did not produce valid response, attempting Claude fallback")
            except Exception as e:
                logger.warning(f"Local LLM failed with {str(e)}, falling back to Claude API")

        # Fallback to Claude API if configured
        if self.claude_provider and self.claude_provider.health_check():
            try:
                return self._run_claude(context, start_time)
            except Exception as e:
                logger.error(f"Claude fallback also failed: {str(e)}")

        # If neither succeeded, return status
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        error_msg = "Local LLM is offline/unavailable"
        if self.claude_provider and self.claude_provider.api_key:
            error_msg += " and Claude fallback failed or was rate limited"
        else:
            error_msg += " and no Claude API key configured"

        return AIAnalysisResult(
            available=False,
            status=AIStatus.UNAVAILABLE,
            provider="hybrid",
            model=self.config.model,
            latency_ms=round(elapsed_ms, 2),
            error=error_msg,
        )

    def _run_local(self, context: Any, start_time: float) -> AIAnalysisResult:
        """Run analysis on local Ollama server."""
        if not self.local_provider.health_check():
            return AIAnalysisResult(
                available=False,
                status=AIStatus.UNAVAILABLE,
                provider=self.local_provider.name,
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Local runtime '{self.local_provider.name}' offline at {self.config.base_url}",
            )

        if not self.local_provider.is_model_available(self.config.model):
            return AIAnalysisResult(
                available=False,
                status=AIStatus.MODEL_NOT_FOUND,
                provider=self.local_provider.name,
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Model '{self.config.model}' not installed in local runtime",
            )

        messages = build_prompt_messages(context)
        raw_response = self.local_provider.generate(
            messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            timeout=self.config.timeout,
            model_override=self.config.model,
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return parse_ai_response(
            raw_response,
            self.local_provider.name,
            self.config.model,
            elapsed_ms,
            self.config,
        )

    def _run_claude(self, context: Any, start_time: float) -> AIAnalysisResult:
        """Run analysis via Claude API with token-optimized prompt."""
        if not self.claude_provider:
            raise AIProviderError("Claude provider not initialized")

        # Use token-optimized prompt to minimize token count & latency
        messages = build_claude_optimized_messages(context)
        raw_response = self.claude_provider.generate(
            messages,
            temperature=self.config.temperature,
            max_tokens=self.config.claude_max_tokens,
            timeout=self.config.claude_timeout,
            model_override=self.config.claude_model,
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return parse_ai_response(
            raw_response,
            "claude",
            self.config.claude_model,
            elapsed_ms,
            self.config,
        )
