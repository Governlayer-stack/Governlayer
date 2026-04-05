"""Centralized configuration — all secrets and settings from environment."""

import os
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

    # Stripe billing
    stripe_api_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_starter: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Email (Resend preferred, SMTP fallback)
    resend_api_key: str = ""
    email_from: str = "GovernLayer <noreply@governlayer.ai>"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_user: str = ""
    smtp_password: str = ""

    # Drift detection
    drift_model: str = "all-MiniLM-L6-v2"
    drift_threshold: float = 0.3

    # Admin
    admin_key: str = ""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: str = "https://www.governlayer.ai,https://governlayer.ai"

    # Observability
    sentry_dsn: str = ""
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "text"

    # Policy
    policy_version: str = "3.0.0"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False, "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.secret_key == _DEFAULT_SECRET:
        if os.getenv("TESTING") == "true" or os.getenv("CI") == "true":
            warnings.warn(
                "SECRET_KEY is using the insecure default. Set SECRET_KEY in your .env file.",
                stacklevel=2,
            )
        else:
            raise RuntimeError(
                "SECRET_KEY is set to the insecure default 'CHANGE-ME-IN-PRODUCTION'. "
                "Set a secure SECRET_KEY in your .env file or environment variables before starting. "
                "For testing, set TESTING=true or CI=true to bypass this check."
            )
    return s
