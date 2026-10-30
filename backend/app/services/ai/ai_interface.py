from abc import ABC, abstractmethod
from app.services.ai.ai_schemas import AIEvidenceInput, AIAnalysisResult


class AIProvider(ABC):
    """
    Common interface for AEGIS AI Intelligence Providers (Local Ollama and Cloud Claude).
    Both providers must adhere to this contract.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier of provider (e.g. 'local_ollama', 'cloud_claude')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Active model name."""
        pass

    @property
    @abstractmethod
    def is_cloud(self) -> bool:
        """True if external network/cloud transmission is involved."""
        pass

    @abstractmethod
    async def check_availability(self) -> bool:
        """
        Lightweight check to verify whether the provider is reachable and operational.
        Should not execute heavy prompts.
        """
        pass

    @abstractmethod
    async def analyze(self, evidence: AIEvidenceInput) -> AIAnalysisResult:
        """
        Executes structured threat analysis on normalized evidence.
        Must handle its own timeouts, validate JSON response, and return AIAnalysisResult.
        """
        pass
