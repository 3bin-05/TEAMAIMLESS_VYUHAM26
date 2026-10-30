from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AEGIS"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"

    DATABASE_URL: str = "sqlite:///./data/aegis.db"

    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Phase 3 Hybrid AI Intelligence Engine Settings
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = ""  # If blank, auto-discovered from local Ollama tags

    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-haiku-20241022"

    AEGIS_AI_MODE: str = "AUTO"  # AUTO, LOCAL_ONLY, CLOUD_ONLY, DISABLED
    AEGIS_CLOUD_AI_ENABLED: bool = False  # Cloud consent flag: disabled by default
    AEGIS_AI_TIMEOUT_SECONDS: int = 20
    AEGIS_AI_HEALTH_CHECK_INTERVAL: int = 300

    RDAP_BASE_URL: str = "https://rdap.org/domain/"
    ML_MODEL_PATH: str = "ml/model.joblib"

    SAFE_CACHE_TTL: int = 900
    CRITICAL_CACHE_TTL: int = 86400
    SUSPICIOUS_CACHE_TTL: int = 180

    REQUEST_TIMEOUT: int = 8

    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/aegis.log"

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()