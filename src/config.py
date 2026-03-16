"""Centralized configuration — all secrets and settings from environment."""

import warnings
from functools import lru_cache

from pydantic_settings import BaseSettings

_DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION"


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql://localhost/governlayer"

    # Auth
    secret_key: str = _DEFAULT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24

    # LLM
    groq_api_key: str = ""
    llm_model: str = "llama-3.3-70b-versatile"

    # Ollama (local inference)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3:8b"
    use_local_llm: bool = False

    # OpenRouter (universal gateway — 500+ models)
    openrouter_api_key: str = ""

    # Achonye orchestration
    achonye_prefer_local: bool = True      # Route simple tasks to Ollama
    achonye_consensus_critical: bool = True # Multi-LLM validation on critical tasks
    achonye_leader_model: str = "claude-opus"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Drift detection
    drift_model: str = "all-MiniLM-L6-v2"
    drift_threshold: float = 0.3

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: str = "https://governlayer.ai"

    # Policy
    policy_version: str = "1.0.0"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False, "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.secret_key == _DEFAULT_SECRET:
        warnings.warn(
            "SECRET_KEY is using the insecure default. Set SECRET_KEY in your .env file.",
            stacklevel=2,
        )
    return s
