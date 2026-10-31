import os
from dataclasses import dataclass, field

DEFAULT_AI_ENABLED = True
DEFAULT_AI_PROVIDER = "hybrid"
DEFAULT_AI_MODEL = "qwen3:4b-instruct"
DEFAULT_AI_BASE_URL = "http://localhost:11434"
DEFAULT_AI_TIMEOUT = 10.0
DEFAULT_AI_TEMPERATURE = 0.1
DEFAULT_AI_MAX_TOKENS = 512
DEFAULT_AI_MAX_FINDINGS = 5
DEFAULT_AI_MAX_TEXT_LENGTH = 1000

DEFAULT_CLAUDE_MODEL = "claude-3-5-haiku-latest"
DEFAULT_CLAUDE_TIMEOUT = 8.0
DEFAULT_CLAUDE_MAX_TOKENS = 350


@dataclass
class AIConfig:
    """Centralized configuration for Aegis AI module supporting Hybrid (Local Ollama + Claude API)."""
    enabled: bool = field(
        default_factory=lambda: os.getenv("AEGIS_AI_ENABLED", "true").lower() == "true"
    )
    provider: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_PROVIDER", DEFAULT_AI_PROVIDER).lower()
    )
    model: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_MODEL", DEFAULT_AI_MODEL)
    )
    base_url: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_BASE_URL", DEFAULT_AI_BASE_URL)
    )
    timeout: float = field(
        default_factory=lambda: float(os.getenv("AEGIS_AI_TIMEOUT", str(DEFAULT_AI_TIMEOUT)))
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("AEGIS_AI_TEMPERATURE", str(DEFAULT_AI_TEMPERATURE)))
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_TOKENS", str(DEFAULT_AI_MAX_TOKENS)))
    )
    max_findings: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_FINDINGS", str(DEFAULT_AI_MAX_FINDINGS)))
    )
    max_text_length: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_TEXT_LENGTH", str(DEFAULT_AI_MAX_TEXT_LENGTH)))
    )
    # Claude API / Hackathon configuration
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", os.getenv("CLAUDE_API_KEY", "")).strip()
    )
    claude_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", os.getenv("AEGIS_CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL))
    )
    claude_timeout: float = field(
        default_factory=lambda: float(os.getenv("AEGIS_CLAUDE_TIMEOUT", str(DEFAULT_CLAUDE_TIMEOUT)))
    )
    claude_max_tokens: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_CLAUDE_MAX_TOKENS", str(DEFAULT_CLAUDE_MAX_TOKENS)))
    )
