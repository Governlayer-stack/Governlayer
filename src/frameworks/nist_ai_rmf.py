"""NIST AI Risk Management Framework — policy rule mapping.

Citations refer to NIST AI 100-1, "Artificial Intelligence Risk Management
Framework (AI RMF 1.0)", National Institute of Standards and Technology,
January 2023, and the companion NIST AI 600-1 "Generative AI Profile"
(July 2024).

The AI RMF is structured around four core functions:
    GOVERN   — cultivate a culture of risk management
    MAP      — establish context and frame risks
    MEASURE  — analyse, assess, benchmark and monitor risks
    MANAGE   — prioritise and act on risks
"""

from __future__ import annotations

from .base import (
    Framework,
    Rule,
    RuleResult,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)


FRAMEWORK_ID = "NIST_AI_RMF"


def _scan_keywords(context: dict, keywords: list[str]) -> list[str]:
    text = " ".join(
        [
            str(context.get("use_case", "")),
            str(context.get("reasoning_trace", "")),
        ]
    ).lower()
    return [kw for kw in keywords if kw.lower() in text]


# ---------------------------------------------------------------------------
# MANAGE 4.1 — Incident response (with evaluator)
# ---------------------------------------------------------------------------

def _eval_incident_response(context: dict) -> RuleResult:
    """Check that the deployment posture references an incident-response capability."""
    markers = [
        "incident response",
        "incident management",
        "runbook",
        "playbook",
        "post-mortem",
        "postmortem",
        "rollback plan",
        "kill switch",
        "rollback procedure",
        "on-call",
        "on call rotation",
    ]
    matches = _scan_keywords(context, markers)
    passed = len(matches) >= 1
    finding = (
        f"Incident-response markers detected: {', '.join(matches)}."
        if passed
        else (
            "No incident-response capability referenced. NIST AI RMF MANAGE 4.1 "
            "calls for plans for post-deployment AI system monitoring, including "
            "mechanisms for prompt response to incidents, including a clearly "
            "defined process for escalation and rollback."
        )
    )
    return RuleResult(
        rule_id="NIST_AI_RMF.MANAGE_4.1",
        passed=passed,
        severity=SEVERITY_HIGH,
        finding=finding,
        evidence={"matched_markers": matches},
    )


# ---------------------------------------------------------------------------
# Static rules — one per AI RMF subcategory, real citations.
# ---------------------------------------------------------------------------

_RULES: list[Rule] = [
    # ---- GOVERN -----------------------------------------------------------
    Rule(
        id="NIST_AI_RMF.GOVERN_1.1",
        framework_id=FRAMEWORK_ID,
        title="Legal and regulatory requirements involving AI are understood",
        description=(
            "GOVERN 1.1: Legal and regulatory requirements involving AI are "
            "understood, managed, and documented. Organisations must maintain "
            "a record of applicable laws and regulations (e.g. sectoral rules, "
            "privacy law, anti-discrimination law) and operationalise them in "
            "policies and procedures."
        ),
        severity=SEVERITY_HIGH,
        category="governance",
        triggers=[
            "ai policy", "ai governance policy", "compliance policy",
            "regulatory mapping", "legal review", "gdpr", "hipaa", "ccpa",
            "policy document",
        ],
        citations=["NIST AI 100-1, GOVERN 1.1"],
    ),
    Rule(
        id="NIST_AI_RMF.GOVERN_2.1",
        framework_id=FRAMEWORK_ID,
        title="Roles, responsibilities and lines of communication are documented",
        description=(
            "GOVERN 2.1: Roles and responsibilities and lines of communication "
            "related to mapping, measuring, and managing AI risks are documented "
            "and are clear to individuals and teams throughout the organisation. "
            "RACI matrices or equivalent accountability mappings should exist "
            "for AI system owners, ML engineers, governance, and audit."
        ),
        severity=SEVERITY_HIGH,
        category="governance",
        triggers=[
            "raci", "accountability", "model owner", "system owner",
            "responsible party", "responsibility matrix", "role assignment",
            "responsible ai officer", "ai ethics board",
        ],
        citations=["NIST AI 100-1, GOVERN 2.1"],
    ),
    # ---- MAP --------------------------------------------------------------
    Rule(
        id="NIST_AI_RMF.MAP_1.1",
        framework_id=FRAMEWORK_ID,
        title="Intended purposes, beneficial uses and context are established",
        description=(
            "MAP 1.1: Intended purposes, potentially beneficial uses, "
            "context-specific laws, norms and expectations, and prospective "
            "settings in which the AI system will be deployed are understood "
            "and documented. Context must include geography, sector, and the "
            "population of users and affected persons."
        ),
        severity=SEVERITY_MEDIUM,
        category="mapping",
        triggers=[
            "intended use", "intended purpose", "use case description",
            "deployment context", "target users", "stakeholders",
            "affected population", "context of use",
        ],
        citations=["NIST AI 100-1, MAP 1.1"],
    ),
    Rule(
        id="NIST_AI_RMF.MAP_1.5",
        framework_id=FRAMEWORK_ID,
        title="AI system categorization and risk tolerance are determined",
        description=(
            "MAP 1.5: Organisational risk tolerances are determined and "
            "documented. AI systems are categorised by use case, criticality, "
            "data sensitivity, and impact on rights, safety, and the "
            "environment. Categorisation drives the depth of MEASURE and "
            "MANAGE activities applied."
        ),
        severity=SEVERITY_MEDIUM,
        category="mapping",
        triggers=[
            "risk tier", "risk category", "risk classification",
            "system tier", "criticality", "impact assessment",
            "risk appetite", "risk tolerance",
        ],
        citations=["NIST AI 100-1, MAP 1.5"],
    ),
    # ---- MEASURE ----------------------------------------------------------
    Rule(
        id="NIST_AI_RMF.MEASURE_2.3",
        framework_id=FRAMEWORK_ID,
        title="Trustworthy characteristics are measured with appropriate metrics",
        description=(
            "MEASURE 2.3: AI system performance and assurance of trustworthy "
            "characteristics — validity, reliability, safety, security, "
            "resilience, accountability, transparency, explainability, "
            "privacy, and fairness — are demonstrated through documented "
            "measurement with appropriate metrics."
        ),
        severity=SEVERITY_HIGH,
        category="measurement",
        triggers=[
            "accuracy", "precision", "recall", "f1", "auc", "rouge",
            "bleu", "perplexity", "robustness metric", "fairness metric",
            "explainability metric", "model metrics", "evaluation metric",
        ],
        citations=["NIST AI 100-1, MEASURE 2.3"],
    ),
    Rule(
        id="NIST_AI_RMF.MEASURE_2.7",
        framework_id=FRAMEWORK_ID,
        title="Performance is monitored in deployment",
        description=(
            "MEASURE 2.7: AI system security and resilience — as identified in "
            "the MAP function — are evaluated and documented. MEASURE 4.2 "
            "further requires ongoing monitoring mechanisms (data drift, "
            "concept drift, performance degradation) once the system is "
            "operating in production."
        ),
        severity=SEVERITY_HIGH,
        category="measurement",
        triggers=[
            "drift detection", "data drift", "concept drift", "model monitoring",
            "performance monitoring", "production monitoring", "observability",
            "telemetry", "alerting",
        ],
        citations=["NIST AI 100-1, MEASURE 2.7", "NIST AI 100-1, MEASURE 4.2"],
    ),
    # ---- MANAGE -----------------------------------------------------------
    Rule(
        id="NIST_AI_RMF.MANAGE_1.3",
        framework_id=FRAMEWORK_ID,
        title="Risk treatment decisions are made and documented",
        description=(
            "MANAGE 1.3: Responses to the AI risks deemed high priority — as "
            "identified by MAP and MEASURE — are developed, planned, and "
            "documented. Risk treatment options (mitigate, transfer, avoid, "
            "accept) and residual-risk acceptance must be recorded with named "
            "accountable owners."
        ),
        severity=SEVERITY_HIGH,
        category="management",
        triggers=[
            "risk treatment", "risk mitigation", "risk acceptance",
            "residual risk", "compensating control", "mitigation plan",
            "remediation",
        ],
        citations=["NIST AI 100-1, MANAGE 1.3"],
    ),
    Rule(
        id="NIST_AI_RMF.MANAGE_4.1",
        framework_id=FRAMEWORK_ID,
        title="Post-deployment monitoring and incident response",
        description=(
            "MANAGE 4.1: Post-deployment AI system monitoring plans are "
            "implemented, including mechanisms for capturing and evaluating "
            "input from users and other relevant AI actors, appeal and "
            "override, decommissioning, incident response, recovery, and "
            "change management."
        ),
        severity=SEVERITY_HIGH,
        category="management",
        triggers=[
            "incident response", "incident management", "runbook", "playbook",
            "post-mortem", "postmortem", "rollback", "kill switch", "on-call",
            "decommissioning", "change management",
        ],
        evaluator=_eval_incident_response,
        citations=["NIST AI 100-1, MANAGE 4.1"],
    ),
]


NIST_AI_RMF = Framework(
    id=FRAMEWORK_ID,
    name="NIST AI Risk Management Framework",
    version="AI RMF 1.0 (NIST AI 100-1)",
    jurisdiction="United States (voluntary, federal reference)",
    description=(
        "NIST AI 100-1, Artificial Intelligence Risk Management Framework "
        "(AI RMF 1.0), January 2023. A voluntary framework intended for "
        "organisations designing, developing, deploying, or using AI systems "
        "to manage the many risks of AI and promote trustworthy and "
        "responsible development and use of AI systems. Structured around "
        "four core functions: GOVERN, MAP, MEASURE, MANAGE."
    ),
    source_url="https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
    rules=_RULES,
)
