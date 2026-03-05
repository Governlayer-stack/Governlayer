"""Shared API dependencies — LLM client, search, settings."""

from langchain_groq import ChatGroq
from langchain_community.tools import DuckDuckGoSearchRun
from functools import lru_cache

from src.config import get_settings


@lru_cache()
def get_llm():
    settings = get_settings()
    return ChatGroq(model=settings.llm_model)


@lru_cache()
def get_search():
    return DuckDuckGoSearchRun()
