"""Central registry of loaded GovernLayer frameworks.

Imports every shipped framework and exposes lookup + evaluation helpers.
New frameworks are registered here once and become available across the
API, MCP server, and downstream agents.
"""

from __future__ import annotations

from typing import Optional

from .base import Framework, Rule, RuleResult
from .eu_ai_act import EU_AI_ACT
from .nist_ai_rmf import NIST_AI_RMF


# Ordered registry — registration order is preserved in listing endpoints.
_FRAMEWORKS: list[Framework] = [
    EU_AI_ACT,
    NIST_AI_RMF,
]

_BY_ID: dict[str, Framework] = {f.id: f for f in _FRAMEWORKS}


def get_all_frameworks() -> list[Framework]:
    """Return every registered framework in registration order."""
    return list(_FRAMEWORKS)


def get_framework(framework_id: str) -> Optional[Framework]:
    """Look up a framework by its stable id (case-insensitive)."""
    if not framework_id:
        return None
    return _BY_ID.get(framework_id) or _BY_ID.get(framework_id.upper())


def _build_context(use_case_text: str, reasoning_trace: str) -> dict:
    return {
        "use_case": use_case_text or "",
        "reasoning_trace": reasoning_trace or "",
    }


def triggered_rules(
    use_case_text: str,
    reasoning_trace: str,
    framework_id: Optional[str] = None,
) -> list[Rule]:
    """Return every Rule whose triggers match the combined input text.

    If framework_id is provided, restrict to that framework. Otherwise scan
    every registered framework.
    """
    haystack = f"{use_case_text or ''}\n{reasoning_trace or ''}"
    if framework_id:
        fw = get_framework(framework_id)
        frameworks = [fw] if fw else []
    else:
        frameworks = _FRAMEWORKS
    out: list[Rule] = []
    for fw in frameworks:
        for rule in fw.rules:
            if rule.is_triggered(haystack):
                out.append(rule)
    return out


def evaluate_use_case(
    use_case_text: str,
    reasoning_trace: str,
    framework_id: Optional[str] = None,
) -> list[RuleResult]:
    """Run every triggered rule's evaluator and return the results.

    Rules without an evaluator are still returned with an informational
    RuleResult (passed=True, automated=False in evidence) so the caller
    can surface them for manual review.
    """
    context = _build_context(use_case_text, reasoning_trace)
    results: list[RuleResult] = []
    for rule in triggered_rules(use_case_text, reasoning_trace, framework_id):
        results.append(rule.run(context))
    return results


def framework_summary() -> list[dict]:
    """Compact summary of all registered frameworks — used by the API listing."""
    return [fw.to_metadata() for fw in _FRAMEWORKS]
