import os
import json
import logging
from typing import List, Dict, Any, Optional

from local_ai.exceptions import AIProviderError, AITimeoutError
from .base import LocalAIProvider

logger = logging.getLogger("aegis.ai.claude")


class ClaudeProvider(LocalAIProvider):
    """Production adapter for Anthropic Claude API utilizing the official Anthropic SDK and token optimization."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "claude-3-5-haiku-latest",
    ):
        self.api_key = (api_key or "").strip()
        self.default_model = default_model
        self._client = None
        if self.api_key:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Anthropic client: {e}")

    @property
    def name(self) -> str:
        return "claude"

    def health_check(self) -> bool:
        """Check whether an API key is configured."""
        return bool(self.api_key)

    def is_model_available(self, model_name: str) -> bool:
        """Claude models are hosted cloud endpoints; available if API key is present."""
        return bool(self.api_key)

    def generate(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 350,
        timeout: float = 8.0,
        model_override: Optional[str] = None,
    ) -> str:
        """Execute chat completion using Anthropic Claude Messages API adhering to official SDK."""
        if not self.api_key:
            raise AIProviderError("Anthropic API key is not configured.")

        model = model_override or self.default_model

        # Extract system prompt into top-level parameter for Anthropic messages API
        system_chunks: List[str] = []
        anthropic_messages: List[Dict[str, str]] = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_chunks.append(content)
            else:
                anthropic_messages.append({"role": role, "content": content})

        if not anthropic_messages:
            anthropic_messages = [{"role": "user", "content": "Analyze target security telemetry."}]

        system_instruction = "\n\n".join(system_chunks) if system_chunks else None

        # Execute using official Anthropic SDK
        try:
            from anthropic import Anthropic, APIError, AuthenticationError, APITimeoutError

            client = self._client or Anthropic(api_key=self.api_key, timeout=timeout)
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_instruction if system_instruction else "",
                messages=anthropic_messages,
            )

            answer = "\n".join(
                block.text for block in response.content
                if getattr(block, "type", None) == "text"
            ).strip()

            if not answer:
                raise AIProviderError("Claude returned empty text completion")

            return answer

        except AuthenticationError as exc:
            raise AIProviderError(f"Anthropic Authentication Failed (401): {exc}")
        except APITimeoutError as exc:
            raise AITimeoutError(f"Claude API timed out after {timeout}s: {exc}")
        except APIError as exc:
            raise AIProviderError(f"Claude API request failed: {exc.__class__.__name__}: {exc}")
        except Exception as exc:
            raise AIProviderError(f"Unexpected Claude failure: {exc}")
