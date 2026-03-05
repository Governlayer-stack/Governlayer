"""Intelligent task router — sends each task to the optimal model.

The router analyzes incoming tasks and routes them based on:
1. Task complexity (simple -> local, complex -> cloud)
2. Required capability (reasoning, code, search, privacy)
3. Cost optimization (prefer local/cheap when quality is sufficient)
4. Availability (graceful fallback if a provider is down)

This is the nervous system of the Achonye architecture.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from langchain_core.language_models import BaseChatModel

from src.llm.providers import (
    ModelCapability,
    ModelTier,
    get_best_for,
    get_model,
    get_profile,
    MODEL_REGISTRY,
)

logger = logging.getLogger(__name__)


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"      # Classification, formatting, extraction
    SIMPLE = "simple"        # Summarization, simple Q&A
    MODERATE = "moderate"    # Analysis, code review, multi-step
    COMPLEX = "complex"      # Architecture, deep reasoning, novel problems
    CRITICAL = "critical"    # Governance decisions, security, compliance


@dataclass
class RoutingDecision:
    """The router's decision about which model(s) to use."""
    primary_model: str
    reason: str
    task_complexity: TaskComplexity
    capability_needed: ModelCapability
    estimated_tokens: int = 0
    requires_consensus: bool = False
    consensus_models: list[str] | None = None


# Keyword patterns for capability detection
_CAPABILITY_PATTERNS: dict[ModelCapability, list[str]] = {
    ModelCapability.REASONING: [
        r"reason", r"analyz", r"evaluat", r"assess", r"decision",
        r"governance", r"policy", r"trade.?off", r"compare",
    ],
    ModelCapability.CODE_GENERATION: [
        r"code", r"implement", r"function", r"class\b", r"debug",
        r"refactor", r"api", r"endpoint", r"script",
    ],
    ModelCapability.MATH: [
        r"math", r"calculat", r"equation", r"statistic", r"probability",
        r"formula", r"numeric", r"score",
    ],
    ModelCapability.FACT_RETRIEVAL: [
        r"search", r"find", r"current", r"latest", r"news",
        r"regulation", r"law", r"framework", r"standard",
    ],
    ModelCapability.VERIFICATION: [
        r"verify", r"check", r"validate", r"confirm", r"audit",
        r"review", r"correct", r"accurate",
    ],
    ModelCapability.PRIVACY_SENSITIVE: [
        r"private", r"confidential", r"secret", r"pii", r"hipaa",
        r"internal", r"classified", r"sensitive",
    ],
    ModelCapability.GOVERNANCE: [
        r"complian", r"regulat", r"govern", r"eu.?ai.?act", r"nist",
        r"risk", r"drift", r"audit", r"ledger",
    ],
}

# Complexity heuristics
_COMPLEXITY_PATTERNS: dict[TaskComplexity, list[str]] = {
    TaskComplexity.TRIVIAL: [
        r"classify", r"extract", r"format", r"convert", r"list\b",
        r"summarize.{0,20}short", r"yes.?or.?no",
    ],
    TaskComplexity.SIMPLE: [
        r"summarize", r"explain", r"describe", r"translate",
        r"what is", r"define",
    ],
    TaskComplexity.COMPLEX: [
        r"architect", r"design", r"strategy", r"comprehensive",
        r"multi.?step", r"plan", r"novel", r"innovate",
    ],
    TaskComplexity.CRITICAL: [
        r"security", r"compliance", r"breach", r"incident",
        r"legal", r"regulatory", r"enforce", r"block",
    ],
}


def _detect_capability(task: str) -> ModelCapability:
    """Detect the primary capability needed from the task text."""
    task_lower = task.lower()
    scores: dict[ModelCapability, int] = {}

    for capability, patterns in _CAPABILITY_PATTERNS.items():
        score = sum(1 for p in patterns if re.search(p, task_lower))
        if score > 0:
            scores[capability] = score

    if not scores:
        return ModelCapability.REASONING  # default

    return max(scores, key=scores.get)


def _detect_complexity(task: str) -> TaskComplexity:
    """Estimate task complexity from the task text."""
    task_lower = task.lower()

    # Check from highest to lowest
    for complexity in [TaskComplexity.CRITICAL, TaskComplexity.COMPLEX]:
        patterns = _COMPLEXITY_PATTERNS.get(complexity, [])
        if any(re.search(p, task_lower) for p in patterns):
            return complexity

    for complexity in [TaskComplexity.TRIVIAL, TaskComplexity.SIMPLE]:
        patterns = _COMPLEXITY_PATTERNS.get(complexity, [])
        if any(re.search(p, task_lower) for p in patterns):
            return complexity

    # Default: moderate
    word_count = len(task.split())
    if word_count < 20:
        return TaskComplexity.SIMPLE
    return TaskComplexity.MODERATE


# Tier mapping by complexity
_COMPLEXITY_TO_TIER: dict[TaskComplexity, list[ModelTier]] = {
    TaskComplexity.TRIVIAL: [ModelTier.LOCAL],
    TaskComplexity.SIMPLE: [ModelTier.LOCAL, ModelTier.FAST_CLOUD],
    TaskComplexity.MODERATE: [ModelTier.FAST_CLOUD, ModelTier.STANDARD_CLOUD],
    TaskComplexity.COMPLEX: [ModelTier.STANDARD_CLOUD, ModelTier.PREMIUM_CLOUD],
    TaskComplexity.CRITICAL: [ModelTier.PREMIUM_CLOUD],
}


def route_task(
    task: str,
    force_capability: Optional[ModelCapability] = None,
    force_model: Optional[str] = None,
    prefer_local: bool = False,
) -> RoutingDecision:
    """Route a task to the optimal model based on analysis.

    Args:
        task: The task description or prompt
        force_capability: Override auto-detected capability
        force_model: Force a specific model (bypass routing)
        prefer_local: Prefer local models to save tokens

    Returns:
        RoutingDecision with the selected model and reasoning
    """
    if force_model:
        profile = get_profile(force_model)
        return RoutingDecision(
            primary_model=force_model,
            reason=f"Forced to {force_model}",
            task_complexity=TaskComplexity.MODERATE,
            capability_needed=profile.capabilities[0] if profile.capabilities else ModelCapability.REASONING,
        )

    capability = force_capability or _detect_capability(task)
    complexity = _detect_complexity(task)

    # Privacy-sensitive tasks MUST go local
    if capability == ModelCapability.PRIVACY_SENSITIVE:
        prefer_local = True

    primary = get_best_for(capability, prefer_local=prefer_local or complexity in (TaskComplexity.TRIVIAL, TaskComplexity.SIMPLE))

    # Critical tasks require consensus
    requires_consensus = complexity == TaskComplexity.CRITICAL
    consensus_models = None
    if requires_consensus:
        consensus_models = _pick_consensus_panel(capability, exclude=primary)

    return RoutingDecision(
        primary_model=primary,
        reason=_build_reason(capability, complexity, primary, prefer_local),
        task_complexity=complexity,
        capability_needed=capability,
        requires_consensus=requires_consensus,
        consensus_models=consensus_models,
    )


def _pick_consensus_panel(capability: ModelCapability, exclude: str) -> list[str]:
    """Pick 2-3 diverse models for consensus voting."""
    candidates = []
    seen_providers = set()

    for name, profile in MODEL_REGISTRY.items():
        if name == exclude:
            continue
        if capability in profile.capabilities and profile.provider not in seen_providers:
            candidates.append(name)
            seen_providers.add(profile.provider)
            if len(candidates) >= 3:
                break

    return candidates


def _build_reason(
    capability: ModelCapability,
    complexity: TaskComplexity,
    model: str,
    prefer_local: bool,
) -> str:
    profile = get_profile(model)
    parts = [
        f"Complexity={complexity.value}",
        f"Capability={capability.value}",
        f"Model={profile.name}",
        f"Tier={profile.tier.value}",
    ]
    if prefer_local:
        parts.append("LocalPreferred")
    return " | ".join(parts)


def get_routed_model(task: str, **kwargs) -> tuple[BaseChatModel, RoutingDecision]:
    """Convenience: route a task and return both the model and the decision."""
    decision = route_task(task, **kwargs)
    model = get_model(decision.primary_model)
    return model, decision
