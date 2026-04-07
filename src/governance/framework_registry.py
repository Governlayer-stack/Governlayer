"""Framework Registry — lookup, filtering, and batch evaluation of regulatory frameworks.

Provides the public API for the Regulatory-to-Code Compiler:
    - get_framework(framework_id) — Get single framework by ID
    - get_frameworks_by_category(category) — Filter by category
    - get_applicable_frameworks(jurisdiction, industry) — Smart lookup
    - evaluate_all(context, frameworks) — Run all applicable policies against context
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.governance.frameworks import ALL_FRAMEWORKS, CATEGORIES, Framework


# ---------------------------------------------------------------------------
# Build the registry dict (keyed by framework_id)
# ---------------------------------------------------------------------------

FRAMEWORK_REGISTRY: Dict[str, Framework] = {
    fw["framework_id"]: fw for fw in ALL_FRAMEWORKS
}


# ---------------------------------------------------------------------------
# Jurisdiction-to-framework mapping
# ---------------------------------------------------------------------------

# Which frameworks apply by default in each jurisdiction.
# INTERNATIONAL frameworks always apply.
_JURISDICTION_MAP: Dict[str, List[str]] = {
    "US": [
        "NIST_AI_RMF", "US_EO_14110", "CCPA", "HIPAA",
        "NIST_CSF", "SOC_2", "CIS_CONTROLS",
    ],
    "US-CA": [
        "NIST_AI_RMF", "US_EO_14110", "CCPA", "HIPAA",
        "NIST_CSF", "SOC_2", "CIS_CONTROLS",
    ],
    "EU": [
        "EU_AI_ACT", "GDPR",
    ],
    "UK": [
        "UK_AI_ACT", "GDPR",  # UK GDPR still applies post-Brexit
    ],
    "CA": [
        "CANADA_AIDA",
    ],
    "SG": [
        "SINGAPORE_AI_GOV",
    ],
    "CN": [
        "CHINA_AI_REGS",
    ],
}

# Frameworks that always apply regardless of jurisdiction.
_INTERNATIONAL_FRAMEWORKS = [
    fw_id for fw_id, fw in FRAMEWORK_REGISTRY.items()
    if fw["jurisdiction"] == "INTERNATIONAL"
]

# Industry-specific framework additions.
_INDUSTRY_MAP: Dict[str, List[str]] = {
    "healthcare": ["HIPAA"],
    "health": ["HIPAA"],
    "medical": ["HIPAA"],
    "finance": ["SOC_2", "FAIR_RISK", "ISO_27001"],
    "banking": ["SOC_2", "FAIR_RISK", "ISO_27001"],
    "insurance": ["SOC_2", "FAIR_RISK"],
    "government": ["NIST_CSF", "NIST_AI_RMF", "ZERO_TRUST", "CIS_CONTROLS"],
    "defense": ["NIST_CSF", "NIST_AI_RMF", "ZERO_TRUST", "CIS_CONTROLS", "MITRE_ATLAS"],
    "cloud": ["CSA_AI", "SOC_2", "ISO_27001"],
    "saas": ["CSA_AI", "SOC_2", "ISO_27001"],
    "education": ["UNESCO_AI", "IEEE_ETHICS"],
    "research": ["OECD_AI", "IEEE_ETHICS"],
    "general": [],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_framework(framework_id: str) -> Optional[Framework]:
    """Get a single framework by its ID.

    Args:
        framework_id: The framework identifier (e.g. "EU_AI_ACT").

    Returns:
        The framework dict or None if not found.
    """
    return FRAMEWORK_REGISTRY.get(framework_id)


def get_frameworks_by_category(category: str) -> List[Framework]:
    """Get all frameworks belonging to a category.

    Args:
        category: One of: ai_risk_safety, regional_regulations, data_privacy,
                  security_infrastructure, it_governance_risk.

    Returns:
        List of matching frameworks (may be empty).
    """
    return [
        fw for fw in ALL_FRAMEWORKS
        if fw["category"] == category
    ]


def get_applicable_frameworks(
    jurisdiction: Optional[str] = None,
    industry: Optional[str] = None,
) -> List[Framework]:
    """Smart lookup: return frameworks applicable to a jurisdiction and industry.

    Logic:
        1. Always include all INTERNATIONAL frameworks.
        2. Add jurisdiction-specific frameworks.
        3. Add industry-specific frameworks.
        4. Deduplicate while preserving order.

    Args:
        jurisdiction: ISO country code or region (US, EU, UK, CA, SG, CN, etc.)
        industry: Industry vertical (healthcare, finance, government, etc.)

    Returns:
        Deduplicated list of applicable frameworks.
    """
    seen: set = set()
    result: List[Framework] = []

    def _add(fw_id: str) -> None:
        if fw_id not in seen and fw_id in FRAMEWORK_REGISTRY:
            seen.add(fw_id)
            result.append(FRAMEWORK_REGISTRY[fw_id])

    # 1. International frameworks always apply
    for fw_id in _INTERNATIONAL_FRAMEWORKS:
        _add(fw_id)

    # 2. Jurisdiction-specific
    if jurisdiction:
        j = jurisdiction.upper()
        for fw_id in _JURISDICTION_MAP.get(j, []):
            _add(fw_id)

    # 3. Industry-specific
    if industry:
        i = industry.lower()
        for fw_id in _INDUSTRY_MAP.get(i, []):
            _add(fw_id)

    # If nothing matched beyond international, return all
    if not jurisdiction and not industry:
        return list(ALL_FRAMEWORKS)

    return result


def evaluate_framework(
    context: Dict[str, Any],
    framework: Framework,
) -> Dict[str, Any]:
    """Evaluate a single framework's policies against a governance context.

    Args:
        context: Dict with governance context keys (see frameworks.py docstring).
        framework: A framework dict from the registry.

    Returns:
        Evaluation result with violations grouped by severity.
    """
    all_violations: List[Dict[str, str]] = []
    policy_results: List[Dict[str, Any]] = []

    for policy in framework["policies"]:
        eval_fn = policy["evaluate"]
        violations = eval_fn(context)
        passed = len(violations) == 0

        policy_results.append({
            "policy_id": policy["policy_id"],
            "regulation": policy["regulation"],
            "severity": policy["severity"],
            "description": policy["description"],
            "passed": passed,
            "violations": violations,
        })

        all_violations.extend(violations)

    # Group violations by severity
    blocking = [v for v in all_violations if v["severity"] == "BLOCKING"]
    critical = [v for v in all_violations if v["severity"] == "CRITICAL"]
    warnings = [v for v in all_violations if v["severity"] == "WARNING"]
    info = [v for v in all_violations if v["severity"] == "INFO"]

    total_policies = len(policy_results)
    passed_policies = sum(1 for p in policy_results if p["passed"])

    return {
        "framework_id": framework["framework_id"],
        "framework_name": framework["name"],
        "jurisdiction": framework["jurisdiction"],
        "category": framework["category"],
        "total_policies": total_policies,
        "passed_policies": passed_policies,
        "failed_policies": total_policies - passed_policies,
        "compliant": len(blocking) == 0 and len(critical) == 0,
        "blocking_count": len(blocking),
        "critical_count": len(critical),
        "warning_count": len(warnings),
        "info_count": len(info),
        "violations": all_violations,
        "policy_results": policy_results,
    }


def evaluate_all(
    context: Dict[str, Any],
    frameworks: Optional[List[Framework]] = None,
) -> Dict[str, Any]:
    """Run all applicable policies across multiple frameworks against context.

    Args:
        context: Dict with governance context keys.
        frameworks: List of frameworks to evaluate. If None, uses all 25.

    Returns:
        Comprehensive evaluation report with per-framework results and summary.
    """
    if frameworks is None:
        frameworks = ALL_FRAMEWORKS

    framework_results: List[Dict[str, Any]] = []
    total_violations: List[Dict[str, str]] = []

    for fw in frameworks:
        result = evaluate_framework(context, fw)
        framework_results.append(result)
        total_violations.extend(result["violations"])

    # Aggregate severity counts
    blocking = [v for v in total_violations if v["severity"] == "BLOCKING"]
    critical = [v for v in total_violations if v["severity"] == "CRITICAL"]
    warnings = [v for v in total_violations if v["severity"] == "WARNING"]
    info = [v for v in total_violations if v["severity"] == "INFO"]

    compliant_frameworks = sum(1 for r in framework_results if r["compliant"])
    total_frameworks = len(framework_results)

    # Determine overall compliance decision
    if len(blocking) > 0:
        decision = "BLOCK"
    elif len(critical) > 0:
        decision = "REVIEW_REQUIRED"
    elif len(warnings) > 0:
        decision = "CONDITIONAL_PASS"
    else:
        decision = "PASS"

    return {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks_evaluated": total_frameworks,
        "frameworks_compliant": compliant_frameworks,
        "frameworks_non_compliant": total_frameworks - compliant_frameworks,
        "total_violations": len(total_violations),
        "blocking_count": len(blocking),
        "critical_count": len(critical),
        "warning_count": len(warnings),
        "info_count": len(info),
        "decision": decision,
        "blocking_violations": blocking,
        "critical_violations": critical,
        "warning_violations": warnings,
        "info_violations": info,
        "framework_results": framework_results,
        "categories_evaluated": list({fw["category"] for fw in frameworks}),
        "category_labels": CATEGORIES,
    }


def list_frameworks() -> List[Dict[str, str]]:
    """Return a summary list of all 25 frameworks for discovery.

    Returns:
        List of dicts with framework_id, name, jurisdiction, category.
    """
    return [
        {
            "framework_id": fw["framework_id"],
            "name": fw["name"],
            "jurisdiction": fw["jurisdiction"],
            "category": fw["category"],
            "category_label": CATEGORIES.get(fw["category"], fw["category"]),
            "policy_count": len(fw["policies"]),
            "version": fw.get("version", ""),
        }
        for fw in ALL_FRAMEWORKS
    ]


def get_category_summary() -> Dict[str, Any]:
    """Return a summary of frameworks grouped by category.

    Returns:
        Dict with category keys and lists of framework summaries.
    """
    summary: Dict[str, Any] = {}
    for cat_id, cat_label in CATEGORIES.items():
        frameworks = get_frameworks_by_category(cat_id)
        summary[cat_id] = {
            "label": cat_label,
            "framework_count": len(frameworks),
            "frameworks": [
                {
                    "framework_id": fw["framework_id"],
                    "name": fw["name"],
                    "jurisdiction": fw["jurisdiction"],
                    "policy_count": len(fw["policies"]),
                }
                for fw in frameworks
            ],
        }
    return summary
