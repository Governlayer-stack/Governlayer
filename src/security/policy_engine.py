"""Cedar-inspired Policy Engine — default-deny runtime governance for AI agents.

Every agent tool call is evaluated against policies before execution.
Policies follow Cedar semantics:
  - Default DENY — everything is forbidden unless explicitly permitted
  - PERMIT rules grant access
  - FORBID rules override permits (deny wins)
  - Conditions refine when rules apply

Production deployment would integrate with AWS Cedar SDK.
This implementation preserves the same semantics with a lightweight engine.
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Effect(StrEnum):
    PERMIT = "permit"
    FORBID = "forbid"


class EnforcementResult(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class PolicyCondition:
    """Optional condition that must be true for the policy to apply."""
    field: str          # e.g. "time_of_day", "data_classification", "risk_level"
    operator: str       # "eq", "neq", "in", "gt", "lt", "contains"
    value: object       # comparison value


@dataclass
class Policy:
    """A single authorization policy for agent actions."""
    policy_id: str
    name: str
    effect: Effect
    principal: str              # agent_id or "*" for all agents
    action: str                 # tool/action name or "*" for all
    resource: str               # resource identifier or "*" for all
    conditions: list[PolicyCondition] = field(default_factory=list)
    priority: int = 0           # higher priority evaluated first
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    enabled: bool = True


@dataclass
class EvaluationLog:
    """Audit record of a policy evaluation."""
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    result: EnforcementResult
    matched_policy: Optional[str]   # policy_id or None (default deny)
    reason: str
    context: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Cedar-inspired policy evaluation engine with default-deny posture.

    Evaluation order:
    1. Collect all matching FORBID policies -> if any match, DENY
    2. Collect all matching PERMIT policies -> if any match, ALLOW
    3. Default -> DENY (fail-closed)

    This matches Cedar's semantics where forbid always wins over permit.
    """

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}
        self._evaluation_log: list[EvaluationLog] = []
        self._lock = threading.Lock()

    # --- Policy CRUD ---

    def add_policy(self, policy: Policy) -> str:
        """Register a new policy. Returns the policy_id."""
        with self._lock:
            self._policies[policy.policy_id] = policy
        logger.info(
            "Policy added: id=%s name=%s effect=%s principal=%s action=%s",
            policy.policy_id[:8], policy.name, policy.effect,
            policy.principal, policy.action,
        )
        return policy.policy_id

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID. Returns True if removed."""
        with self._lock:
            return self._policies.pop(policy_id, None) is not None

    def update_policy(self, policy_id: str, **kwargs) -> bool:
        """Update fields on an existing policy."""
        with self._lock:
            policy = self._policies.get(policy_id)
            if not policy:
                return False
            for key, val in kwargs.items():
                if hasattr(policy, key):
                    setattr(policy, key, val)
            return True

    def list_policies(self) -> list[dict]:
        """Return all policies as serializable dicts."""
        with self._lock:
            return [
                {
                    "policy_id": p.policy_id,
                    "name": p.name,
                    "effect": p.effect.value,
                    "principal": p.principal,
                    "action": p.action,
                    "resource": p.resource,
                    "conditions": [
                        {"field": c.field, "operator": c.operator, "value": c.value}
                        for c in p.conditions
                    ],
                    "priority": p.priority,
                    "description": p.description,
                    "enabled": p.enabled,
                    "created_at": p.created_at.isoformat(),
                }
                for p in sorted(
                    self._policies.values(),
                    key=lambda p: p.priority,
                    reverse=True,
                )
            ]

    # --- Evaluation ---

    def evaluate(
        self,
        agent_id: str,
        action: str,
        resource: str,
        context: Optional[dict] = None,
    ) -> tuple[EnforcementResult, str]:
        """Evaluate whether an agent action is permitted.

        Args:
            agent_id: The agent requesting authorization.
            action: The tool or action being invoked.
            resource: The target resource.
            context: Optional context dict for condition evaluation.

        Returns:
            Tuple of (result, reason) — ALLOW or DENY with explanation.
        """
        context = context or {}
        now = datetime.now(timezone.utc)

        with self._lock:
            enabled_policies = [
                p for p in self._policies.values() if p.enabled
            ]

        # Sort by priority (highest first)
        enabled_policies.sort(key=lambda p: p.priority, reverse=True)

        # Phase 1: Check FORBID rules — any match = DENY
        for policy in enabled_policies:
            if policy.effect != Effect.FORBID:
                continue
            if self._matches(policy, agent_id, action, resource, context):
                reason = f"FORBID by policy '{policy.name}' ({policy.policy_id[:8]})"
                self._log_evaluation(
                    now, agent_id, action, resource,
                    EnforcementResult.DENY, policy.policy_id, reason, context,
                )
                return EnforcementResult.DENY, reason

        # Phase 2: Check PERMIT rules — any match = ALLOW
        for policy in enabled_policies:
            if policy.effect != Effect.PERMIT:
                continue
            if self._matches(policy, agent_id, action, resource, context):
                reason = f"PERMIT by policy '{policy.name}' ({policy.policy_id[:8]})"
                self._log_evaluation(
                    now, agent_id, action, resource,
                    EnforcementResult.ALLOW, policy.policy_id, reason, context,
                )
                return EnforcementResult.ALLOW, reason

        # Phase 3: Default DENY
        reason = "Default DENY — no matching permit policy"
        self._log_evaluation(
            now, agent_id, action, resource,
            EnforcementResult.DENY, None, reason, context,
        )
        return EnforcementResult.DENY, reason

    def _matches(
        self,
        policy: Policy,
        agent_id: str,
        action: str,
        resource: str,
        context: dict,
    ) -> bool:
        """Check if a policy matches the request."""
        # Principal match
        if policy.principal != "*" and policy.principal != agent_id:
            return False

        # Action match (supports "category:*" wildcards)
        if policy.action != "*":
            if ":" in policy.action and policy.action.endswith(":*"):
                prefix = policy.action[:-1]  # "llm:*" -> "llm:"
                if not action.startswith(prefix):
                    return False
            elif policy.action != action:
                return False

        # Resource match
        if policy.resource != "*" and policy.resource != resource:
            return False

        # Condition evaluation
        for cond in policy.conditions:
            if not self._eval_condition(cond, context):
                return False

        return True

    def _eval_condition(self, cond: PolicyCondition, context: dict) -> bool:
        """Evaluate a single condition against the context."""
        actual = context.get(cond.field)
        if actual is None:
            return False

        op = cond.operator
        expected = cond.value

        if op == "eq":
            return actual == expected
        elif op == "neq":
            return actual != expected
        elif op == "in":
            return actual in expected if isinstance(expected, (list, set, tuple)) else False
        elif op == "gt":
            return actual > expected
        elif op == "lt":
            return actual < expected
        elif op == "contains":
            return expected in actual if isinstance(actual, (str, list)) else False
        else:
            logger.warning("Unknown condition operator: %s", op)
            return False

    def _log_evaluation(
        self,
        timestamp: datetime,
        agent_id: str,
        action: str,
        resource: str,
        result: EnforcementResult,
        matched_policy: Optional[str],
        reason: str,
        context: dict,
    ) -> None:
        """Record an evaluation in the audit log."""
        entry = EvaluationLog(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            resource=resource,
            result=result,
            matched_policy=matched_policy,
            reason=reason,
            context=context,
        )
        with self._lock:
            self._evaluation_log.append(entry)
            # Keep log bounded
            if len(self._evaluation_log) > 10000:
                self._evaluation_log = self._evaluation_log[-5000:]

        log_fn = logger.info if result == EnforcementResult.ALLOW else logger.warning
        log_fn(
            "Policy eval: agent=%s action=%s resource=%s result=%s reason=%s",
            agent_id, action, resource, result.value, reason,
        )

    def get_evaluation_log(self, limit: int = 100, agent_id: Optional[str] = None) -> list[dict]:
        """Return recent evaluation log entries."""
        with self._lock:
            entries = list(self._evaluation_log)

        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]

        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "agent_id": e.agent_id,
                "action": e.action,
                "resource": e.resource,
                "result": e.result.value,
                "matched_policy": e.matched_policy,
                "reason": e.reason,
            }
            for e in reversed(entries[-limit:])
        ]

    def get_stats(self) -> dict:
        """Return enforcement statistics."""
        with self._lock:
            total = len(self._evaluation_log)
            allowed = sum(1 for e in self._evaluation_log if e.result == EnforcementResult.ALLOW)
            denied = total - allowed
            policy_count = len(self._policies)
            enabled_count = sum(1 for p in self._policies.values() if p.enabled)

        return {
            "total_evaluations": total,
            "allowed": allowed,
            "denied": denied,
            "deny_rate": round(denied / total * 100, 1) if total else 0,
            "total_policies": policy_count,
            "enabled_policies": enabled_count,
        }


# ---------------------------------------------------------------------------
# Singleton + factory helpers
# ---------------------------------------------------------------------------

_engine: Optional[PolicyEngine] = None
_engine_lock = threading.Lock()


def get_policy_engine() -> PolicyEngine:
    """Get or create the singleton PolicyEngine."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PolicyEngine()
                _seed_default_policies(_engine)
    return _engine


def create_policy(
    name: str,
    effect: str,
    principal: str = "*",
    action: str = "*",
    resource: str = "*",
    conditions: Optional[list[dict]] = None,
    priority: int = 0,
    description: str = "",
) -> Policy:
    """Helper to create a Policy from simple arguments."""
    conds = []
    for c in (conditions or []):
        conds.append(PolicyCondition(
            field=c["field"],
            operator=c["operator"],
            value=c["value"],
        ))

    return Policy(
        policy_id=str(uuid.uuid4()),
        name=name,
        effect=Effect(effect),
        principal=principal,
        action=action,
        resource=resource,
        conditions=conds,
        priority=priority,
        description=description,
    )


def _seed_default_policies(engine: PolicyEngine) -> None:
    """Seed sensible default policies for GovernLayer agents."""

    # Allow all agents to read audit records
    engine.add_policy(create_policy(
        name="Allow audit reads",
        effect="permit",
        action="audit:read",
        resource="*",
        priority=10,
        description="All agents can read the audit ledger",
    ))

    # Allow all agents to invoke LLM for governance tasks
    engine.add_policy(create_policy(
        name="Allow LLM governance calls",
        effect="permit",
        action="llm:invoke",
        resource="*",
        priority=10,
        description="All agents can invoke LLMs for governance analysis",
    ))

    # Allow risk scoring
    engine.add_policy(create_policy(
        name="Allow risk scoring",
        effect="permit",
        action="risk:score",
        resource="*",
        priority=10,
        description="All agents can compute risk scores",
    ))

    # Allow drift detection
    engine.add_policy(create_policy(
        name="Allow drift detection",
        effect="permit",
        action="drift:detect",
        resource="*",
        priority=10,
        description="All agents can run drift detection",
    ))

    # Forbid direct database writes without governance agent role
    engine.add_policy(create_policy(
        name="Forbid unscoped DB writes",
        effect="forbid",
        action="db:write",
        resource="*",
        conditions=[{"field": "agent_role", "operator": "neq", "value": "governance"}],
        priority=100,
        description="Only governance-role agents can write directly to the database",
    ))

    # Forbid credential access for non-operator agents
    engine.add_policy(create_policy(
        name="Forbid raw credential access",
        effect="forbid",
        action="credential:raw_access",
        resource="*",
        priority=100,
        description="No agent may access raw credentials — use JIT vault instead",
    ))

    # Allow ledger writes for governance agents
    engine.add_policy(create_policy(
        name="Allow ledger writes",
        effect="permit",
        principal="*",
        action="ledger:write",
        resource="*",
        conditions=[{"field": "agent_role", "operator": "eq", "value": "governance"}],
        priority=50,
        description="Governance agents can append to the immutable ledger",
    ))

    # Allow vendor assessment
    engine.add_policy(create_policy(
        name="Allow vendor assessments",
        effect="permit",
        action="vendor:assess",
        resource="*",
        priority=10,
        description="All agents can run vendor risk assessments",
    ))

    logger.info("Seeded %d default policies", len(engine.list_policies()))
