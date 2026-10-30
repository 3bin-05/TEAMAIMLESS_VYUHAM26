from datetime import datetime, timezone
import logging
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis")

# Known LLM families compatible with general text reasoning
COMPATIBLE_MODEL_FAMILIES = [
    "qwen", "llama", "mistral", "gemma", "phi",
    "deepseek", "vicuna", "orca", "neural", "falcon"
]


class OllamaRuntimeDetector:
    """
    Discovers, verifies, and health-checks local Ollama installations:
    1. Tests whether the Ollama HTTP API is reachable.
    2. Discovers installed models via /api/tags.
    3. Selects a compatible model (configured in settings or best available).
    4. Probes inference capability with a lightweight health test.
    5. Caches health state to prevent discovery overhead on every URL scan.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 15.0,
        cache_ttl: int | None = None
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.cache_ttl = cache_ttl or settings.AEGIS_AI_HEALTH_CHECK_INTERVAL

        # State tracking
        self._last_checked: datetime | None = None
        self._is_reachable: bool = False
        self._models_found: list[str] = []
        self._selected_model: str | None = None
        self._inference_verified: bool = False
        self._last_error: str | None = None

    @property
    def is_available(self) -> bool:
        """True if Ollama is reachable, a model is selected, and inference succeeded."""
        return self._is_reachable and (self._selected_model is not None) and self._inference_verified

    @property
    def is_reachable(self) -> bool:
        return self._is_reachable

    @property
    def models_found(self) -> list[str]:
        return list(self._models_found)

    @property
    def selected_model(self) -> str | None:
        return self._selected_model

    @property
    def inference_verified(self) -> bool:
        return self._inference_verified

    @property
    def last_checked(self) -> datetime | None:
        return self._last_checked

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def _is_cache_fresh(self) -> bool:
        if self._last_checked is None:
            return False
        age_seconds = (datetime.now(timezone.utc) - self._last_checked).total_seconds()
        return age_seconds < self.cache_ttl

    async def detect(self, force_refresh: bool = False) -> bool:
        """
        Executes complete discovery and health probe.
        Uses cached result if within cache_ttl unless force_refresh is True.
        """
        if not force_refresh and self._is_cache_fresh():
            return self.is_available

        self._last_checked = datetime.now(timezone.utc)
        self._is_reachable = False
        self._models_found = []
        self._selected_model = None
        self._inference_verified = False
        self._last_error = None

        tags_url = f"{self.base_url}/api/tags"

        # Step 1: Reachability & Model Tags
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(tags_url)
                if resp.status_code != 200:
                    self._last_error = f"Ollama endpoint responded with HTTP {resp.status_code}"
                    logger.warning(self._last_error)
                    return False

                data = resp.json()
                models = data.get("models", [])
                self._is_reachable = True

                for m in models:
                    name = m.get("name") or m.get("model")
                    if name:
                        self._models_found.append(str(name))

        except httpx.ConnectError:
            self._last_error = f"Connection refused to Ollama daemon at {self.base_url}"
            logger.info(self._last_error)
            return False
        except httpx.TimeoutException:
            self._last_error = f"Timeout connecting to Ollama daemon at {self.base_url} ({self.timeout}s)"
            logger.warning(self._last_error)
            return False
        except Exception as exc:
            self._last_error = f"Ollama reachability check error: {exc}"
            logger.warning(self._last_error)
            return False

        if not self._models_found:
            self._last_error = "Ollama runtime reachable, but zero models are currently installed"
            logger.info(self._last_error)
            return False

        # Step 2: Select compatible model
        configured_model = settings.OLLAMA_MODEL.strip()
        if configured_model and configured_model in self._models_found:
            self._selected_model = configured_model
        elif configured_model and any(configured_model in m for m in self._models_found):
            # Match partial tag (e.g. 'qwen3' matching 'qwen3:4b-instruct')
            matched = next(m for m in self._models_found if configured_model in m)
            self._selected_model = matched
        else:
            # Pick first model that matches compatible general reasoning families
            compatible = [
                m for m in self._models_found
                if any(fam in m.lower() for fam in COMPATIBLE_MODEL_FAMILIES)
            ]
            self._selected_model = compatible[0] if compatible else self._models_found[0]

        # Step 3: Lightweight inference probe
        probe_success = await self._probe_inference(self._selected_model)
        self._inference_verified = probe_success
        return self.is_available

    async def _probe_inference(self, model_name: str) -> bool:
        """Sends a lightweight prompt to verify the model can actually execute inference."""
        generate_url = f"{self.base_url}/api/generate"
        payload = {
            "model": model_name,
            "prompt": "Say OK",
            "stream": False,
            "options": {"num_predict": 4}
        }

        try:
            probe_timeout = max(self.timeout, float(settings.AEGIS_AI_TIMEOUT_SECONDS))
            async with httpx.AsyncClient(timeout=probe_timeout) as client:
                resp = await client.post(generate_url, json=payload)
                if resp.status_code == 200:
                    resp_json = resp.json()
                    if "response" in resp_json:
                        logger.info(f"Ollama local model '{model_name}' verified operational.")
                        return True
                    else:
                        self._last_error = f"Ollama probe returned malformed response: {resp_json}"
                        return False
                else:
                    self._last_error = f"Ollama inference probe returned HTTP {resp.status_code}"
                    return False
        except Exception as exc:
            self._last_error = f"Ollama inference health probe failed: {exc}"
            logger.warning(self._last_error)
            return False
