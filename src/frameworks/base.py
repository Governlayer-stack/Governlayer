"""Core data model for the framework policy-rules engine.

A Framework is a versioned collection of Rules. A Rule is a single,
citable obligation drawn from a regulation or standard. Each Rule may
provide an evaluator callable that inspects an inbound use case +
reasoning trace and returns a RuleResult (passed / failed / evidence).

Rules without an evaluator are still useful — the registry will return
them as "triggered" matches based on keyword triggers and let downstream
agents (e.g. compliance_agent) reason about applicability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# Severity levels — ordered most-severe first for sorting convenience.
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
}


@dataclass
class RuleResult:
    """Outcome of running a single Rule's evaluator."""

    rule_id: str
    passed: bool
    severity: str
    finding: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "passed": self.passed,
            "severity": self.severity,
            "finding": self.finding,
            "evidence": self.evidence,
        }


@dataclass
class Rule:
    """A single, citable governance rule.

    Attributes:
        id: Stable rule identifier (e.g. "EU_AI_ACT.ART_9.1"). Used in
            audit trails and ledger entries.
        framework_id: Parent framework id.
        title: Short human label.
        description: What the rule checks and why.
        severity: One of CRITICAL / HIGH / MEDIUM / LOW.
        category: Free-form grouping (risk_management, data_governance,
            transparency, human_oversight, governance, mapping, measurement,
            management, prohibited_practice).
        triggers: Lowercase keyword list — if any keyword appears in the
            use_case + reasoning_trace text, the rule is "triggered".
        evaluator: Optional callable taking a context dict
            ({"use_case": str, "reasoning_trace": str, ...}) and returning
            a RuleResult. If None, the rule is informational-only and
            triggered rules without evaluators are returned with passed=True
            and a finding noting that no automated check exists.
        citations: Source citations — article numbers, section identifiers,
            URLs. Always at least one entry.
    """

    id: str
    framework_id: str
    title: str
    description: str
    severity: str
    category: str
    triggers: list[str] = field(default_factory=list)
    evaluator: Optional[Callable[[dict], RuleResult]] = None
    citations: list[str] = field(default_factory=list)

    def is_triggered(self, text: str) -> bool:
        """Return True if any trigger keyword appears in the lowercased text."""
        if not self.triggers:
            return False
        haystack = text.lower()
        return any(trigger.lower() in haystack for trigger in self.triggers)

    def run(self, context: dict) -> RuleResult:
        """Run the evaluator if one exists, else return an informational pass."""
        if self.evaluator is not None:
            return self.evaluator(context)
        return RuleResult(
            rule_id=self.id,
            passed=True,
            severity=self.severity,
            finding=(
                f"Rule '{self.title}' triggered by keyword match. No automated "
                "evaluator is wired — manual review recommended."
            ),
            evidence={"automated": False, "triggers": self.triggers},
        )

    def to_dict(self, include_evaluator_flag: bool = True) -> dict:
        d: dict[str, Any] = {
            "id": self.id,
            "framework_id": self.framework_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "triggers": list(self.triggers),
            "citations": list(self.citations),
        }
        if include_evaluator_flag:
            d["has_evaluator"] = self.evaluator is not None
        return d


@dataclass
class Framework:
    """A versioned collection of Rules drawn from a single regulation/standard."""

    id: str
    name: str
    version: str
    jurisdiction: str
    rules: list[Rule] = field(default_factory=list)
    description: str = ""
    source_url: str = ""

    def rule_count(self) -> int:
        return len(self.rules)

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def to_metadata(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "jurisdiction": self.jurisdiction,
            "description": self.description,
            "source_url": self.source_url,
            "rule_count": self.rule_count(),
            "categories": sorted({r.category for r in self.rules}),
            "severity_breakdown": {
                sev: sum(1 for r in self.rules if r.severity == sev)
                for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)
            },
        }

    def to_dict(self) -> dict:
        return {
            **self.to_metadata(),
            "rules": [r.to_dict() for r in self.rules],
        }
