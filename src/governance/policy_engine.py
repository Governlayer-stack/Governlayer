"""Policy-as-Code Engine — configurable governance rules with safe evaluation."""

from datetime import datetime
from typing import Any, Dict, List, Optional


DEFAULT_POLICY = {
    "name": "default_governance_policy",
    "version": "1.0",
    "rules": [
        {
            "id": "risk_threshold",
            "description": "Risk score must be below threshold",
            "condition": "risk_score < 70",
            "severity": "high",
            "action": "block",
        },
        {
            "id": "drift_threshold",
            "description": "Behavioral drift must be within acceptable range",
            "condition": "drift_score < 0.3",
            "severity": "high",
            "action": "alert",
        },
        {
            "id": "fairness_check",
            "description": "Disparate impact ratio must meet 4/5ths rule",
            "condition": "disparate_impact >= 0.8",
            "severity": "critical",
            "action": "block",
        },
        {
            "id": "pii_check",
            "description": "No PII detected in model outputs",
            "condition": "pii_count == 0",
            "severity": "critical",
            "action": "block",
        },
        {
            "id": "injection_check",
            "description": "No prompt injection detected",
            "condition": "injection_detected == False",
            "severity": "critical",
            "action": "block",
        },
        {
            "id": "model_lifecycle",
            "description": "Model must be in production lifecycle",
            "condition": "lifecycle == 'production'",
            "severity": "medium",
            "action": "warn",
        },
    ],
}


SAFE_NAMES = {"True": True, "False": False, "None": None}


def _safe_eval(condition: str, context: Dict[str, Any]) -> bool:
    """Safely evaluate a policy condition against context variables."""
    try:
        safe_globals = {"__builtins__": {}}
        safe_locals = {**SAFE_NAMES, **context}
        return bool(eval(condition, safe_globals, safe_locals))
    except Exception:
        return False


def evaluate_policy(
    context: Dict[str, Any],
    policy: Optional[Dict] = None,
) -> Dict:
    """Evaluate all policy rules against the given context."""
    policy = policy or DEFAULT_POLICY
    results = []
    violations = []
    warnings = []

    for rule in policy.get("rules", []):
        passed = _safe_eval(rule["condition"], context)
        result = {
            "rule_id": rule["id"],
            "description": rule["description"],
            "condition": rule["condition"],
            "passed": passed,
            "severity": rule.get("severity", "medium"),
            "action": rule.get("action", "alert"),
        }
        results.append(result)

        if not passed:
            if rule.get("action") == "block":
                violations.append(result)
            else:
                warnings.append(result)

    all_passed = len(violations) == 0
    return {
        "policy_name": policy.get("name", "unknown"),
        "policy_version": policy.get("version", "1.0"),
        "evaluated_at": datetime.utcnow().isoformat(),
        "context_keys": list(context.keys()),
        "total_rules": len(results),
        "passed_rules": sum(1 for r in results if r["passed"]),
        "failed_rules": sum(1 for r in results if not r["passed"]),
        "violations": violations,
        "warnings": warnings,
        "all_rules": results,
        "compliant": all_passed,
        "decision": "allow" if all_passed else "block",
    }
