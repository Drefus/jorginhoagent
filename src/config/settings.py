"""Settings and configuration management."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # LLM Configuration
    llm_provider: Literal["openai", "anthropic", "huggingface"] = "openai"
    llm_model: str = "gpt-4"
    llm_api_key: str = ""
    llm_temperature: float = 0.7
    llm_max_tokens: int = 4096

    # Hugging Face Configuration
    huggingface_api_key: str = ""
    huggingface_model_id: str = "microsoft/codebert-base"

    # GitHub Configuration
    github_token: str = ""
    github_repo_owner: str = ""
    github_repo_name: str = ""

    # Vector Store Configuration
    chroma_persist_dir: str = "./data/chroma"
    vector_store_type: Literal["chroma", "pinecone", "weaviate"] = "chroma"

    # Database Configuration
    database_url: str = "sqlite:///./data/jorginhoagent.db"
    redis_url: str = "redis://localhost:6379/0"

    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "./logs/app.log"

    # Analysis Configuration
    bandit_level: Literal["low", "medium", "high"] = "high"
    include_context_analysis: bool = True
    include_rag_lookup: bool = True

    # API Configuration
    api_port: int = 8000
    api_host: str = "0.0.0.0"

    # Feature Flags
    enable_github_integration: bool = False
    enable_rag: bool = True
    enable_async_analysis: bool = True

    # Application Settings
    debug: bool = False
    project_name: str = "JorginhoAgent"

    class Config:
        """Pydantic config."""

        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
