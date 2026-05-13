"""EU AI Act (Regulation (EU) 2024/1689) — policy rule mapping.

Citations refer to the consolidated text of Regulation (EU) 2024/1689 of
the European Parliament and of the Council of 13 June 2024 laying down
harmonised rules on artificial intelligence (Artificial Intelligence Act).

Key enforcement milestones:
- 2 Feb 2025 — Prohibited practices (Article 5) become enforceable
- 2 Aug 2025 — GPAI obligations apply
- 2 Aug 2026 — High-risk AI systems obligations apply
- 2 Aug 2027 — Full applicability to existing high-risk systems
"""

from __future__ import annotations

from .base import (
    Framework,
    Rule,
    RuleResult,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)


FRAMEWORK_ID = "EU_AI_ACT"


# ---------------------------------------------------------------------------
# Helper — keyword scan used by several evaluators
# ---------------------------------------------------------------------------

def _scan_keywords(context: dict, keywords: list[str]) -> list[str]:
    """Return the subset of keywords found in use_case + reasoning_trace."""
    text = " ".join(
        [
            str(context.get("use_case", "")),
            str(context.get("reasoning_trace", "")),
        ]
    ).lower()
    return [kw for kw in keywords if kw.lower() in text]


# ---------------------------------------------------------------------------
# Article 5 — Prohibited AI practices (CRITICAL)
# ---------------------------------------------------------------------------

def _eval_social_scoring(context: dict) -> RuleResult:
    keywords = [
        "social score",
        "social scoring",
        "social credit",
        "credit social",
        "trustworthiness score",
        "trustworthiness assessment",
        "citizen rating",
        "behavior score",
        "behavioural score",
        "social rating",
        "reputation score",
    ]
    matches = _scan_keywords(context, keywords)
    passed = len(matches) == 0
    finding = (
        "No social-scoring keywords detected in use case or reasoning trace."
        if passed
        else (
            "Potential Article 5(1)(c) violation — the system appears to engage in "
            "social scoring of natural persons based on social behaviour or personal "
            "characteristics. This practice is PROHIBITED under the EU AI Act."
        )
    )
    return RuleResult(
        rule_id="EU_AI_ACT.ART_5.1.C",
        passed=passed,
        severity=SEVERITY_CRITICAL,
        finding=finding,
        evidence={"matched_keywords": matches},
    )


def _eval_biometric_identification(context: dict) -> RuleResult:
    keywords = [
        "real-time biometric",
        "real time biometric",
        "live facial recognition",
        "live face recognition",
        "public space surveillance",
        "rt-rbi",
        "remote biometric identification",
        "mass surveillance",
        "facial recognition in public",
    ]
    matches = _scan_keywords(context, keywords)
    passed = len(matches) == 0
    finding = (
        "No real-time remote biometric identification indicators detected."
        if passed
        else (
            "Potential Article 5(1)(h) violation — real-time remote biometric "
            "identification in publicly accessible spaces by law-enforcement is "
            "PROHIBITED except for narrowly-defined exceptions (e.g. targeted search "
            "for victims of serious crime). Deployment requires prior judicial or "
            "administrative authorisation."
        )
    )
    return RuleResult(
        rule_id="EU_AI_ACT.ART_5.1.H",
        passed=passed,
        severity=SEVERITY_CRITICAL,
        finding=finding,
        evidence={"matched_keywords": matches},
    )


def _eval_exploitative_ai(context: dict) -> RuleResult:
    keywords = [
        "exploit vulnerability",
        "exploit vulnerabilities",
        "target children",
        "target minors",
        "manipulate behavior",
        "manipulate behaviour",
        "subliminal",
        "dark pattern",
        "dark patterns",
        "cognitive manipulation",
        "exploit elderly",
        "exploit disability",
    ]
    matches = _scan_keywords(context, keywords)
    passed = len(matches) == 0
    finding = (
        "No indicators of exploitative or subliminal manipulation detected."
        if passed
        else (
            "Potential Article 5(1)(a)–(b) violation — AI systems that deploy "
            "subliminal techniques beyond a person's consciousness or exploit "
            "vulnerabilities (age, disability, socio-economic situation) to "
            "materially distort behaviour in a way likely to cause harm are "
            "PROHIBITED."
        )
    )
    return RuleResult(
        rule_id="EU_AI_ACT.ART_5.1.AB",
        passed=passed,
        severity=SEVERITY_CRITICAL,
        finding=finding,
        evidence={"matched_keywords": matches},
    )


# ---------------------------------------------------------------------------
# Article 9 — Risk-management system (HIGH)
# ---------------------------------------------------------------------------

def _eval_risk_management_system(context: dict) -> RuleResult:
    """Look for evidence that a continuous risk-management system exists.

    Article 9 requires providers of high-risk AI to establish, implement,
    document and maintain a risk-management system as a continuous iterative
    process throughout the lifecycle.
    """
    evidence_markers = [
        "risk management system",
        "risk management process",
        "risk register",
        "risk assessment",
        "risk treatment",
        "iterative risk",
        "lifecycle risk",
        "risk monitoring",
    ]
    matches = _scan_keywords(context, evidence_markers)
    passed = len(matches) >= 1
    finding = (
        f"Risk-management indicators detected: {', '.join(matches)}."
        if passed
        else (
            "No evidence of a documented, continuous risk-management system. "
            "Article 9(1)–(2) requires a documented iterative risk-management "
            "process covering identification, estimation, evaluation, and "
            "treatment of risks throughout the AI system lifecycle."
        )
    )
    return RuleResult(
        rule_id="EU_AI_ACT.ART_9.1",
        passed=passed,
        severity=SEVERITY_HIGH,
        finding=finding,
        evidence={"matched_keywords": matches},
    )


# ---------------------------------------------------------------------------
# Static (no-evaluator) rules — registered for triggered review by the
# downstream compliance agent. Citations are real EU AI Act articles.
# ---------------------------------------------------------------------------

_STATIC_RULES: list[Rule] = [
    Rule(
        id="EU_AI_ACT.ART_9.2",
        framework_id=FRAMEWORK_ID,
        title="Risk testing prior to placing on market",
        description=(
            "Article 9(6)–(8): the risk-management system must include testing "
            "procedures (including against pre-defined metrics and probabilistic "
            "thresholds) sufficient to ensure the high-risk AI system performs "
            "consistently for its intended purpose and complies with the "
            "requirements set out in Chapter III, Section 2."
        ),
        severity=SEVERITY_HIGH,
        category="risk_management",
        triggers=[
            "high-risk", "high risk", "production deployment", "go live",
            "release to production", "model testing", "evaluation harness",
        ],
        citations=["EU AI Act Article 9(6)", "EU AI Act Article 9(7)", "EU AI Act Article 9(8)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_10.2",
        framework_id=FRAMEWORK_ID,
        title="Training, validation and testing data quality",
        description=(
            "Article 10(2)–(3): training, validation and testing datasets must "
            "be subject to data-governance practices appropriate for the "
            "intended purpose, including relevant design choices, data "
            "collection processes, data preparation operations (annotation, "
            "labelling, cleaning, enrichment), formulation of assumptions, "
            "examination for biases, and identification of data gaps."
        ),
        severity=SEVERITY_HIGH,
        category="data_governance",
        triggers=[
            "training data", "training dataset", "validation data", "test data",
            "data pipeline", "labelling", "labeling", "annotation",
            "data preparation", "data cleaning",
        ],
        citations=["EU AI Act Article 10(2)", "EU AI Act Article 10(3)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_10.5",
        framework_id=FRAMEWORK_ID,
        title="Bias detection and mitigation in training data",
        description=(
            "Article 10(2)(f)–(g) and 10(5): datasets must be examined for "
            "possible biases likely to affect health, safety, fundamental rights "
            "or lead to prohibited discrimination. Providers may process special "
            "categories of personal data strictly for bias detection and "
            "correction, subject to appropriate safeguards including "
            "pseudonymisation and access controls."
        ),
        severity=SEVERITY_HIGH,
        category="data_governance",
        triggers=[
            "bias", "fairness", "discrimination", "protected attribute",
            "demographic parity", "disparate impact", "equal opportunity",
            "gender", "race", "ethnicity",
        ],
        citations=["EU AI Act Article 10(2)(f)", "EU AI Act Article 10(2)(g)", "EU AI Act Article 10(5)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_13",
        framework_id=FRAMEWORK_ID,
        title="Transparency and provision of information to deployers",
        description=(
            "Article 13: high-risk AI systems must be designed and developed "
            "so their operation is sufficiently transparent to enable deployers "
            "to interpret the system's output and use it appropriately. They "
            "must be accompanied by instructions for use that include provider "
            "identity, intended purpose, level of accuracy, foreseeable misuse, "
            "human-oversight measures, expected lifetime, and required "
            "maintenance and care measures."
        ),
        severity=SEVERITY_HIGH,
        category="transparency",
        triggers=[
            "model card", "system card", "instructions for use", "documentation",
            "user manual", "deployer information", "intended purpose",
            "transparency", "explainability", "interpretability",
        ],
        citations=["EU AI Act Article 13(1)", "EU AI Act Article 13(2)", "EU AI Act Article 13(3)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_14",
        framework_id=FRAMEWORK_ID,
        title="Human oversight measures",
        description=(
            "Article 14: high-risk AI systems must be designed so they can be "
            "effectively overseen by natural persons during the period in which "
            "they are in use. Oversight measures shall enable the human to "
            "understand system capacities and limitations, remain aware of "
            "automation bias, correctly interpret the output, decide not to use "
            "the output, and intervene or interrupt the system (including via a "
            "'stop' button)."
        ),
        severity=SEVERITY_HIGH,
        category="human_oversight",
        triggers=[
            "human oversight", "human in the loop", "human-in-the-loop", "hitl",
            "human review", "manual override", "kill switch", "stop button",
            "automation bias", "human approval",
        ],
        citations=["EU AI Act Article 14(1)", "EU AI Act Article 14(4)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_50",
        framework_id=FRAMEWORK_ID,
        title="Transparency for AI-generated or manipulated content",
        description=(
            "Article 50(2) and 50(4): providers of generative AI systems must "
            "ensure outputs are marked in a machine-readable format and "
            "detectable as artificially generated or manipulated. Deployers of "
            "AI systems generating deep fakes must disclose that the content "
            "has been artificially generated or manipulated."
        ),
        severity=SEVERITY_MEDIUM,
        category="transparency",
        triggers=[
            "generative", "synthetic media", "deepfake", "deep fake",
            "ai-generated content", "ai generated content", "watermark",
            "content provenance", "c2pa", "synthetic image", "synthetic video",
        ],
        citations=["EU AI Act Article 50(2)", "EU AI Act Article 50(4)"],
    ),
]


# ---------------------------------------------------------------------------
# Assemble the framework
# ---------------------------------------------------------------------------

_EVALUATED_RULES: list[Rule] = [
    Rule(
        id="EU_AI_ACT.ART_5.1.A_B",
        framework_id=FRAMEWORK_ID,
        title="Prohibition of subliminal and exploitative AI",
        description=(
            "Article 5(1)(a)–(b) prohibits placing on the market or using AI "
            "systems that deploy subliminal techniques beyond a person's "
            "consciousness, or purposefully manipulative or deceptive techniques, "
            "with the objective or effect of materially distorting behaviour and "
            "causing significant harm. Also prohibited: AI that exploits "
            "vulnerabilities due to age, disability, or socio-economic situation."
        ),
        severity=SEVERITY_CRITICAL,
        category="prohibited_practice",
        triggers=[
            "subliminal", "dark pattern", "exploit vulnerability", "target children",
            "target minors", "manipulate behavior", "manipulate behaviour",
            "exploit elderly", "exploit disability", "cognitive manipulation",
        ],
        evaluator=_eval_exploitative_ai,
        citations=["EU AI Act Article 5(1)(a)", "EU AI Act Article 5(1)(b)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_5.1.C",
        framework_id=FRAMEWORK_ID,
        title="Prohibition of social scoring",
        description=(
            "Article 5(1)(c) prohibits AI systems that evaluate or classify "
            "natural persons or groups based on social behaviour or known, "
            "inferred or predicted personal or personality characteristics, with "
            "a social score leading to detrimental or unfavourable treatment in "
            "social contexts unrelated to the contexts in which the data was "
            "generated, or that is unjustified or disproportionate to the "
            "behaviour."
        ),
        severity=SEVERITY_CRITICAL,
        category="prohibited_practice",
        triggers=[
            "social score", "social scoring", "social credit", "credit social",
            "trustworthiness", "citizen rating", "behavior score",
            "behavioural score", "social rating", "reputation score",
        ],
        evaluator=_eval_social_scoring,
        citations=["EU AI Act Article 5(1)(c)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_5.1.H",
        framework_id=FRAMEWORK_ID,
        title="Prohibition of real-time remote biometric identification",
        description=(
            "Article 5(1)(h) prohibits the use of real-time remote biometric "
            "identification systems in publicly accessible spaces for the "
            "purpose of law enforcement, save for narrowly-defined exceptions "
            "(targeted search for specific victims, prevention of a specific "
            "and present threat, localisation of suspects of serious crimes). "
            "Each use requires prior judicial or independent administrative "
            "authorisation."
        ),
        severity=SEVERITY_CRITICAL,
        category="prohibited_practice",
        triggers=[
            "real-time biometric", "real time biometric", "live facial recognition",
            "live face recognition", "public space surveillance", "rt-rbi",
            "remote biometric identification", "mass surveillance",
            "facial recognition in public",
        ],
        evaluator=_eval_biometric_identification,
        citations=["EU AI Act Article 5(1)(h)"],
    ),
    Rule(
        id="EU_AI_ACT.ART_9.1",
        framework_id=FRAMEWORK_ID,
        title="Establish a continuous risk-management system",
        description=(
            "Article 9(1)–(2) requires providers of high-risk AI systems to "
            "establish, implement, document and maintain a risk-management "
            "system. It shall be understood as a continuous iterative process "
            "planned and run throughout the entire lifecycle of the high-risk "
            "AI system, requiring regular systematic review and updating."
        ),
        severity=SEVERITY_HIGH,
        category="risk_management",
        triggers=[
            "risk management", "risk register", "risk assessment",
            "risk treatment", "iterative risk", "lifecycle risk",
            "risk monitoring", "risk process",
        ],
        evaluator=_eval_risk_management_system,
        citations=["EU AI Act Article 9(1)", "EU AI Act Article 9(2)"],
    ),
]


EU_AI_ACT = Framework(
    id=FRAMEWORK_ID,
    name="EU Artificial Intelligence Act",
    version="Regulation (EU) 2024/1689",
    jurisdiction="European Union",
    description=(
        "Regulation (EU) 2024/1689 of the European Parliament and of the "
        "Council of 13 June 2024 laying down harmonised rules on artificial "
        "intelligence (Artificial Intelligence Act). Establishes a risk-based "
        "framework with prohibited practices, obligations for high-risk AI "
        "systems, transparency obligations, and rules for general-purpose AI."
    ),
    source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    rules=_EVALUATED_RULES + _STATIC_RULES,
)
