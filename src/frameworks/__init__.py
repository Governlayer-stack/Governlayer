"""GovernLayer Framework Policy-Rules Engine.

Structured, code-backed models of regulatory and best-practice AI governance
frameworks. Each framework exposes a list of Rules. Rules carry citations,
severity, trigger keywords, and optional evaluator callables that inspect a
use case / reasoning trace and return a deterministic RuleResult.

Currently shipped frameworks:
- EU AI Act (Regulation (EU) 2024/1689)
- NIST AI Risk Management Framework (AI RMF 1.0, NIST AI 100-1)
"""

from .base import Framework, Rule, RuleResult
from .registry import (
    get_all_frameworks,
    get_framework,
    evaluate_use_case,
)

__all__ = [
    "Framework",
    "Rule",
    "RuleResult",
    "get_all_frameworks",
    "get_framework",
    "evaluate_use_case",
]
