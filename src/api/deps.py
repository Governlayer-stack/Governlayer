"""Shared API dependencies — LLM client, search, settings."""

from langchain_community.tools import DuckDuckGoSearchRun
from functools import lru_cache

from src.config import get_settings
from src.llm.providers import get_model, get_best_for, ModelCapability


@lru_cache()
def get_llm():
    """Get the default LLM via Achonye routing (governance-capable)."""
    model_name = get_best_for(ModelCapability.GOVERNANCE, prefer_local=get_settings().use_local_llm)
    return get_model(model_name)


@lru_cache()
def get_search():
    return DuckDuckGoSearchRun()
