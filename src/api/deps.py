"""Shared API dependencies — LLM client, search, settings."""

import logging
from functools import lru_cache

from src.config import get_settings
from src.llm.providers import ModelCapability, get_best_for, get_model

logger = logging.getLogger(__name__)


@lru_cache
def get_llm():
    """Get the default LLM via Achonye routing (governance-capable).

    Prefers Groq (free, fast) when available. Falls back through the
    model registry based on configured API keys.
    """
    settings = get_settings()
    model_name = get_best_for(ModelCapability.GOVERNANCE, prefer_local=settings.use_local_llm)
    logger.info("LLM router selected: %s", model_name)
    return get_model(model_name)


@lru_cache
def get_search():
    try:
        from langchain_community.tools import DuckDuckGoSearchRun
        return DuckDuckGoSearchRun()
    except (ImportError, Exception):
        return None
