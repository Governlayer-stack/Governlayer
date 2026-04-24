"""Unified LLM provider interface — one abstraction, every model.

Supports: Ollama (local), Groq, OpenRouter (500+ models), Gemini, direct APIs.
OpenRouter acts as the universal gateway for cloud models.
Ollama handles all local inference (Llama, Mistral, DeepSeek-R1, Qwen, Phi, Gemma).
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field

from langchain_core.language_models import BaseChatModel

from src.config import get_settings

logger = logging.getLogger(__name__)


class ModelTier(enum.StrEnum):
    """Cost/capability tiers for routing decisions."""
    LOCAL = "local"          # Ollama — zero cost, full privacy
    FAST_CLOUD = "fast"      # Small cloud models — cheap, fast
    STANDARD_CLOUD = "standard"  # Mid-tier cloud — balanced
    PREMIUM_CLOUD = "premium"    # Frontier models — max capability


class ModelCapability(enum.StrEnum):
    """What a model excels at — used for task routing."""
    REASONING = "reasoning"
    CODE_GENERATION = "code_generation"
    FACT_RETRIEVAL = "fact_retrieval"
    VERIFICATION = "verification"
    MATH = "math"
    MULTIMODAL = "multimodal"
    PRIVACY_SENSITIVE = "privacy_sensitive"
    SIMPLE_TASK = "simple_task"
    GOVERNANCE = "governance"
    SEARCH_GROUNDED = "search_grounded"


@dataclass
class ModelProfile:
    """Registration of a model's identity, capabilities, and access path."""
    name: str
    provider: str               # ollama, groq, openrouter, gemini, anthropic
    model_id: str               # Provider-specific model identifier
    tier: ModelTier
    capabilities: list[ModelCapability] = field(default_factory=list)
    context_window: int = 8192
    cost_per_1k_tokens: float = 0.0  # USD, 0 = free/local
    description: str = ""


# --- Model Registry ---
# All models available in the ecosystem, organized by strength

MODEL_REGISTRY: dict[str, ModelProfile] = {
    # === LOCAL (Ollama) — Zero cost, full privacy ===
    "llama3-local": ModelProfile(
        name="Llama 3 8B (Local)",
        provider="ollama",
        model_id="llama3:8b",
        tier=ModelTier.LOCAL,
        capabilities=[
            ModelCapability.SIMPLE_TASK,
            ModelCapability.PRIVACY_SENSITIVE,
            ModelCapability.CODE_GENERATION,
        ],
        context_window=8192,
        description="Fast local model for simple tasks — saves cloud tokens",
    ),
    "mistral-local": ModelProfile(
        name="Mistral 7B (Local)",
        provider="ollama",
        model_id="mistral:7b",
        tier=ModelTier.LOCAL,
        capabilities=[
            ModelCapability.SIMPLE_TASK,
            ModelCapability.CODE_GENERATION,
            ModelCapability.PRIVACY_SENSITIVE,
        ],
        context_window=8192,
        description="Fast local coding model — handles routine tasks offline",
    ),
    "deepseek-r1-local": ModelProfile(
        name="DeepSeek-R1 (Local)",
        provider="ollama",
        model_id="deepseek-r1:14b",
        tier=ModelTier.LOCAL,
        capabilities=[
            ModelCapability.REASONING,
            ModelCapability.MATH,
            ModelCapability.VERIFICATION,
            ModelCapability.PRIVACY_SENSITIVE,
        ],
        context_window=16384,
        description="Local reasoning powerhouse — chain-of-thought, math, verification",
    ),
    "qwen3-local": ModelProfile(
        name="Qwen 3 (Local)",
        provider="ollama",
        model_id="qwen3:8b",
        tier=ModelTier.LOCAL,
        capabilities=[
            ModelCapability.SIMPLE_TASK,
            ModelCapability.REASONING,
            ModelCapability.PRIVACY_SENSITIVE,
        ],
        context_window=8192,
        description="Versatile local model from Alibaba",
    ),
    "phi3-local": ModelProfile(
        name="Phi-3 Mini (Local)",
        provider="ollama",
        model_id="phi3:mini",
        tier=ModelTier.LOCAL,
        capabilities=[
            ModelCapability.SIMPLE_TASK,
            ModelCapability.PRIVACY_SENSITIVE,
        ],
        context_window=4096,
        description="Tiny but capable — ultra-fast for trivial tasks",
    ),

    # === FAST CLOUD (via Groq — hardware-accelerated) ===
    "llama-groq": ModelProfile(
        name="Llama 3.3 70B (Groq)",
        provider="groq",
        model_id="llama-3.3-70b-versatile",
        tier=ModelTier.FAST_CLOUD,
        capabilities=[
            ModelCapability.REASONING,
            ModelCapability.CODE_GENERATION,
            ModelCapability.GOVERNANCE,
        ],
        context_window=128000,
        cost_per_1k_tokens=0.00059,
        description="Groq-accelerated Llama — fast cloud reasoning",
    ),

    # === STANDARD CLOUD (via OpenRouter) ===
    "gemini-pro": ModelProfile(
        name="Gemini 2.5 Pro",
        provider="openrouter",
        model_id="google/gemini-2.5-pro-preview",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.FACT_RETRIEVAL,
            ModelCapability.SEARCH_GROUNDED,
            ModelCapability.REASONING,
            ModelCapability.MULTIMODAL,
        ],
        context_window=1048576,
        cost_per_1k_tokens=0.00125,
        description="1M context, search grounding — the fact-checker",
    ),
    "gpt4o": ModelProfile(
        name="GPT-4o",
        provider="openrouter",
        model_id="openai/gpt-4o",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.VERIFICATION,
            ModelCapability.REASONING,
            ModelCapability.CODE_GENERATION,
            ModelCapability.MULTIMODAL,
        ],
        context_window=128000,
        cost_per_1k_tokens=0.0025,
        description="Strong all-rounder — great for verification and critique",
    ),
    "deepseek-v3": ModelProfile(
        name="DeepSeek V3",
        provider="openrouter",
        model_id="deepseek/deepseek-chat-v3-0324",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.REASONING,
            ModelCapability.MATH,
            ModelCapability.CODE_GENERATION,
        ],
        context_window=65536,
        cost_per_1k_tokens=0.00014,
        description="Extremely cost-effective reasoning — great for math/science",
    ),
    "devstral": ModelProfile(
        name="Devstral 2",
        provider="openrouter",
        model_id="mistralai/devstral-2-latest",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.CODE_GENERATION,
        ],
        context_window=32768,
        cost_per_1k_tokens=0.001,
        description="Top-tier code generation — 72% SWE-bench",
    ),
    "grok": ModelProfile(
        name="Grok 4.1",
        provider="openrouter",
        model_id="x-ai/grok-4-1",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.REASONING,
            ModelCapability.SEARCH_GROUNDED,
            ModelCapability.FACT_RETRIEVAL,
        ],
        context_window=131072,
        cost_per_1k_tokens=0.003,
        description="Live search + huge context — real-time intelligence",
    ),
    "kimi": ModelProfile(
        name="Kimi K2.5",
        provider="openrouter",
        model_id="moonshotai/kimi-k2.5",
        tier=ModelTier.STANDARD_CLOUD,
        capabilities=[
            ModelCapability.MULTIMODAL,
            ModelCapability.CODE_GENERATION,
        ],
        context_window=131072,
        cost_per_1k_tokens=0.002,
        description="Multimodal agentic coding — text, images, video",
    ),

    # === PREMIUM CLOUD — Frontier models ===
    "claude-sonnet": ModelProfile(
        name="Claude Sonnet 4.6",
        provider="openrouter",
        model_id="anthropic/claude-sonnet-4-6",
        tier=ModelTier.PREMIUM_CLOUD,
        capabilities=[
            ModelCapability.VERIFICATION,
            ModelCapability.REASONING,
            ModelCapability.GOVERNANCE,
            ModelCapability.CODE_GENERATION,
        ],
        context_window=200000,
        cost_per_1k_tokens=0.003,
        description="Board member — strategic verification and governance",
    ),
    "claude-opus": ModelProfile(
        name="Claude Opus 4.6 (Achonye)",
        provider="openrouter",
        model_id="anthropic/claude-opus-4-6",
        tier=ModelTier.PREMIUM_CLOUD,
        capabilities=[
            ModelCapability.REASONING,
            ModelCapability.GOVERNANCE,
            ModelCapability.VERIFICATION,
            ModelCapability.CODE_GENERATION,
        ],
        context_window=200000,
        cost_per_1k_tokens=0.015,
        description="THE LEADER — supreme orchestrator, final arbiter",
    ),
}


def _build_ollama_llm(model_id: str) -> BaseChatModel:
    """Create an Ollama-backed chat model."""
    from langchain_ollama import ChatOllama
    settings = get_settings()
    return ChatOllama(
        model=model_id,
        base_url=settings.ollama_base_url,
    )


def _build_groq_llm(model_id: str) -> BaseChatModel:
    """Create a Groq-backed chat model."""
    from langchain_groq import ChatGroq
    return ChatGroq(model=model_id)


def _build_openrouter_llm(model_id: str) -> BaseChatModel:
    """Create an OpenRouter-backed chat model (OpenAI-compatible)."""
    from langchain_openai import ChatOpenAI
    settings = get_settings()
    return ChatOpenAI(
        model=model_id,
        openai_api_key=settings.openrouter_api_key,
        openai_api_base="https://openrouter.ai/api/v1",
    )


_PROVIDER_BUILDERS = {
    "ollama": _build_ollama_llm,
    "groq": _build_groq_llm,
    "openrouter": _build_openrouter_llm,
}


def log_llm_interaction(
    model_name: str,
    prompt_summary: str,
    response_length: int,
    latency_ms: float,
    tokens_used: int | None = None,
) -> None:
    """Log a structured record of an LLM interaction.

    Logs at INFO level with structured data for data provenance.
    Only logs a truncated prompt summary (first 100 chars) to protect privacy.
    """
    summary = prompt_summary[:100] + ("..." if len(prompt_summary) > 100 else "")
    logger.info(
        "LLM interaction: model=%s prompt_summary=%r response_length=%d latency_ms=%.1f tokens_used=%s",
        model_name,
        summary,
        response_length,
        latency_ms,
        tokens_used if tokens_used is not None else "unknown",
    )


class _LoggingModelWrapper:
    """Wraps a LangChain chat model to log all interactions."""

    def __init__(self, model: BaseChatModel, model_name: str):
        self._model = model
        self._model_name = model_name

    def __getattr__(self, name: str):
        return getattr(self._model, name)

    def invoke(self, *args, **kwargs):
        import time
        prompt_summary = str(args[0])[:100] if args else str(kwargs)[:100]
        start = time.perf_counter()
        result = self._model.invoke(*args, **kwargs)
        latency_ms = (time.perf_counter() - start) * 1000
        resp_len = len(result.content) if hasattr(result, "content") else 0
        tokens = None
        if hasattr(result, "response_metadata"):
            usage = result.response_metadata.get("token_usage") or result.response_metadata.get("usage", {})
            if isinstance(usage, dict):
                tokens = usage.get("total_tokens")
        log_llm_interaction(self._model_name, prompt_summary, resp_len, latency_ms, tokens)
        return result

    async def ainvoke(self, *args, **kwargs):
        import time
        prompt_summary = str(args[0])[:100] if args else str(kwargs)[:100]
        start = time.perf_counter()
        result = await self._model.ainvoke(*args, **kwargs)
        latency_ms = (time.perf_counter() - start) * 1000
        resp_len = len(result.content) if hasattr(result, "content") else 0
        tokens = None
        if hasattr(result, "response_metadata"):
            usage = result.response_metadata.get("token_usage") or result.response_metadata.get("usage", {})
            if isinstance(usage, dict):
                tokens = usage.get("total_tokens")
        log_llm_interaction(self._model_name, prompt_summary, resp_len, latency_ms, tokens)
        return result


def get_model(name: str) -> BaseChatModel:
    """Get a LangChain chat model by registry name, wrapped with interaction logging."""
    profile = MODEL_REGISTRY.get(name)
    if not profile:
        raise ValueError(f"Unknown model: {name}. Available: {list(MODEL_REGISTRY.keys())}")
    builder = _PROVIDER_BUILDERS.get(profile.provider)
    if not builder:
        raise ValueError(f"Unknown provider: {profile.provider}")
    model = builder(profile.model_id)
    return _LoggingModelWrapper(model, name)


def get_profile(name: str) -> ModelProfile:
    """Get the profile metadata for a registered model."""
    profile = MODEL_REGISTRY.get(name)
    if not profile:
        raise ValueError(f"Unknown model: {name}")
    return profile


def list_models(
    tier: ModelTier | None = None,
    capability: ModelCapability | None = None,
    only_available: bool = False,
) -> list[ModelProfile]:
    """List available models, optionally filtered by tier or capability."""
    results = []
    for profile in MODEL_REGISTRY.values():
        if tier and profile.tier != tier:
            continue
        if capability and capability not in profile.capabilities:
            continue
        if only_available and not _provider_available(profile.provider):
            continue
        results.append(profile)
    return results


def _provider_available(provider: str) -> bool:
    """Check if a provider has a working API key configured."""
    settings = get_settings()
    if provider == "groq":
        return bool(settings.groq_api_key)
    if provider == "openrouter":
        return bool(settings.openrouter_api_key)
    if provider == "ollama":
        return settings.use_local_llm
    return False


def get_best_for(capability: ModelCapability, prefer_local: bool = False) -> str:
    """Get the best model name for a given capability.

    If prefer_local is True, picks a local model first (saves tokens).
    Otherwise picks the highest-tier model with that capability.
    Only considers models whose providers have API keys configured.
    """
    candidates = [
        (name, p) for name, p in MODEL_REGISTRY.items()
        if capability in p.capabilities and _provider_available(p.provider)
    ]
    if not candidates:
        # Fall back to any model with a working provider
        candidates = [
            (name, p) for name, p in MODEL_REGISTRY.items()
            if _provider_available(p.provider)
        ]
    if not candidates:
        return "llama-groq"  # last resort

    # Default: prefer cost-effective models (Groq free tier) over expensive premium
    # Premium models are reserved for consensus/Achonye escalation, not routine calls
    tier_order = [ModelTier.FAST_CLOUD, ModelTier.STANDARD_CLOUD, ModelTier.PREMIUM_CLOUD, ModelTier.LOCAL]
    if prefer_local:
        tier_order = [ModelTier.LOCAL, ModelTier.FAST_CLOUD, ModelTier.STANDARD_CLOUD, ModelTier.PREMIUM_CLOUD]

    for tier in tier_order:
        for name, p in candidates:
            if p.tier == tier:
                return name

    return candidates[0][0]
