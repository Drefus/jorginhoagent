"""Settings and configuration management."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # LLM Configuration
    llm_provider: Literal["openai", "anthropic", "ollama"] = "openai"
    llm_model: str = "llama3.2:3b"
    llm_api_key: str = ""
    ollama_base_url: str = ""
    ollama_api_key: str = ""
    llm_temperature: float = 0.7
    llm_max_tokens: int = 4096

    # Analysis Configuration
    bandit_level: Literal["low", "medium", "high"] = "high"

    # Application Settings
    debug: bool = False

    class Config:
        """Pydantic config."""

        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
