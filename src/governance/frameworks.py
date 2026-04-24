"""Regulatory-to-Code Compiler — 29 regulatory framework policy templates.

Patent-compliant implementation: ingests legal mandates and converts them into
machine-enforceable policy definitions. Each framework contains concrete,
evaluable policies with real regulatory references, deterministic evaluation
functions (no LLM calls), and remediation guidance.

Governance context dict keys used by evaluation functions:
    use_case, data_types, has_human_oversight, confidence, risk_level,
    pii_detected, model_type, jurisdiction, industry, is_explainable,
    has_bias_testing, makes_autonomous_decisions, handles_personal_data,
    used_in_critical_infrastructure, has_risk_assessment, has_impact_assessment,
    has_data_governance, has_logging, has_qms, training_data_documented,
    has_adversarial_testing, has_input_validation, has_model_access_controls,
    has_data_provenance, has_output_filtering, has_consent_mechanism,
    has_opt_out, data_minimization, has_access_controls, has_encryption,
    has_phi_protection, has_audit_trail, has_incident_response,
    has_asset_inventory, has_mfa, has_network_segmentation,
    has_vulnerability_scanning, has_backup_recovery, has_change_management,
    has_sla, has_service_catalog, risk_quantified, has_cloud_security_policy,
    has_fairness_assessment, has_sustainability_assessment, has_transparency_report,
    has_safety_testing, has_red_teaming, deepfake_detection_enabled,
    algorithmic_transparency, has_data_residency_compliance
"""

from typing import Any, Callable, Dict, List


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

PolicyEvalFn = Callable[[Dict[str, Any]], List[Dict[str, str]]]
Policy = Dict[str, Any]
Framework = Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper: build a violation dict
# ---------------------------------------------------------------------------

def _violation(
    policy_id: str,
    severity: str,
    description: str,
    remediation: str,
) -> Dict[str, str]:
    return {
        "policy_id": policy_id,
        "severity": severity,
        "description": description,
        "remediation": remediation,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1 — AI-SPECIFIC RISK & SAFETY
# ═══════════════════════════════════════════════════════════════════════════


# ---- 1. NIST AI RMF ----

def _eval_nist_ai_rmf_map(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """MAP function: AI system context and risks are identified."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "NIST-AI-RMF-MAP-1", "CRITICAL",
            "No risk assessment documented for AI system",
            "Conduct MAP 1.1 risk identification: document intended purpose, "
            "known limitations, and deployment context per NIST AI RMF MAP function",
        ))
    if not ctx.get("use_case") or ctx.get("use_case") == "general":
        violations.append(_violation(
            "NIST-AI-RMF-MAP-2", "WARNING",
            "AI system use case not specifically defined",
            "Define explicit use case context per MAP 1.5 to enable targeted risk analysis",
        ))
    return violations


def _eval_nist_ai_rmf_measure(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """MEASURE function: AI risks are assessed and tracked."""
    violations = []
    if not ctx.get("has_bias_testing"):
        violations.append(_violation(
            "NIST-AI-RMF-MEASURE-1", "CRITICAL",
            "No bias testing performed on AI system",
            "Implement MEASURE 2.6: test for bias across demographic groups and "
            "document results with disaggregated metrics",
        ))
    if ctx.get("confidence") is not None and ctx["confidence"] < 0.5:
        violations.append(_violation(
            "NIST-AI-RMF-MEASURE-2", "WARNING",
            f"AI confidence {ctx['confidence']:.2f} is below acceptable threshold (0.5)",
            "Investigate low confidence per MEASURE 2.5: assess model calibration "
            "and consider retraining or restricting deployment scope",
        ))
    return violations


def _eval_nist_ai_rmf_manage(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """MANAGE function: AI risks are prioritized and acted upon."""
    violations = []
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "NIST-AI-RMF-MANAGE-1", "CRITICAL",
            "No AI incident response plan documented",
            "Establish MANAGE 4.1 incident response procedures: define escalation paths, "
            "rollback triggers, and communication protocols",
        ))
    return violations


def _eval_nist_ai_rmf_govern(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """GOVERN function: organizational governance culture is established."""
    violations = []
    if not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "NIST-AI-RMF-GOVERN-1", "CRITICAL",
            "No human oversight mechanism for AI system",
            "Implement GOVERN 1.3: establish roles, responsibilities, and oversight "
            "mechanisms for AI risk management",
        ))
    return violations


NIST_AI_RMF: Framework = {
    "framework_id": "NIST_AI_RMF",
    "name": "NIST AI Risk Management Framework",
    "jurisdiction": "US",
    "category": "ai_risk_safety",
    "version": "1.0",
    "url": "https://www.nist.gov/artificial-intelligence/risk-management-framework",
    "policies": [
        {
            "policy_id": "NIST-AI-RMF-MAP",
            "regulation": "NIST AI RMF — MAP Function",
            "severity": "CRITICAL",
            "description": "AI system context, risks, and impacts must be identified and documented",
            "evaluate": _eval_nist_ai_rmf_map,
            "remediation": "Complete MAP function: identify context, risks, and impacts",
        },
        {
            "policy_id": "NIST-AI-RMF-MEASURE",
            "regulation": "NIST AI RMF — MEASURE Function",
            "severity": "CRITICAL",
            "description": "AI risks must be quantitatively assessed with appropriate metrics",
            "evaluate": _eval_nist_ai_rmf_measure,
            "remediation": "Implement measurement protocols for bias, accuracy, and reliability",
        },
        {
            "policy_id": "NIST-AI-RMF-MANAGE",
            "regulation": "NIST AI RMF — MANAGE Function",
            "severity": "CRITICAL",
            "description": "AI risks must be prioritized and acted upon with defined procedures",
            "evaluate": _eval_nist_ai_rmf_manage,
            "remediation": "Establish incident response and risk mitigation procedures",
        },
        {
            "policy_id": "NIST-AI-RMF-GOVERN",
            "regulation": "NIST AI RMF — GOVERN Function",
            "severity": "CRITICAL",
            "description": "Organizational governance culture for responsible AI must be established",
            "evaluate": _eval_nist_ai_rmf_govern,
            "remediation": "Define governance roles, oversight, and accountability structures",
        },
    ],
}


# ---- 2. EU AI Act ----

def _eval_eu_ai_act_art9(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 9: Risk management system."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "EU-AI-ACT-ART9-1", "BLOCKING",
            "No risk management system established for high-risk AI system",
            "Implement Article 9(1): establish, implement, document, and maintain a "
            "risk management system throughout the AI system lifecycle",
        ))
    risk_level = ctx.get("risk_level", "").lower()
    if risk_level in ("high", "critical") and not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "EU-AI-ACT-ART9-2", "BLOCKING",
            "High-risk AI system lacks mandatory safety testing",
            "Per Article 9(5): conduct testing procedures to identify the most "
            "appropriate and targeted risk management measures",
        ))
    return violations


def _eval_eu_ai_act_art10(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 10: Data and data governance."""
    violations = []
    if not ctx.get("has_data_governance"):
        violations.append(_violation(
            "EU-AI-ACT-ART10-1", "CRITICAL",
            "No data governance practices for training, validation, and testing datasets",
            "Implement Article 10(2): establish data governance covering design choices, "
            "data collection, preparation, and bias examination",
        ))
    if not ctx.get("training_data_documented"):
        violations.append(_violation(
            "EU-AI-ACT-ART10-2", "WARNING",
            "Training data provenance and characteristics not documented",
            "Per Article 10(2)(f): document relevant data characteristics including "
            "origin, scope, and known deficiencies",
        ))
    return violations


def _eval_eu_ai_act_art12(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 12: Record-keeping (logging)."""
    violations = []
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "EU-AI-ACT-ART12-1", "CRITICAL",
            "AI system does not maintain automatic logging of events",
            "Implement Article 12(1): ensure automatic recording of events (logs) "
            "throughout the lifetime of the system, traceable to specific decisions",
        ))
    return violations


def _eval_eu_ai_act_art14(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 14: Human oversight."""
    violations = []
    if not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "EU-AI-ACT-ART14-1", "BLOCKING",
            "High-risk AI system lacks human oversight measures",
            "Implement Article 14(1): design system so it can be effectively "
            "overseen by natural persons, including ability to intervene or halt",
        ))
    if ctx.get("makes_autonomous_decisions") and not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "EU-AI-ACT-ART14-2", "BLOCKING",
            "Autonomous decision-making without human oversight violates EU AI Act",
            "Per Article 14(3)(d): ensure human can decide not to use the system "
            "or disregard/reverse its output",
        ))
    return violations


def _eval_eu_ai_act_art17(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 17: Quality management system."""
    violations = []
    if not ctx.get("has_qms"):
        violations.append(_violation(
            "EU-AI-ACT-ART17-1", "CRITICAL",
            "No quality management system (QMS) for high-risk AI system",
            "Implement Article 17(1): establish QMS covering risk management, "
            "data management, record-keeping, and post-market monitoring",
        ))
    return violations


EU_AI_ACT: Framework = {
    "framework_id": "EU_AI_ACT",
    "name": "EU Artificial Intelligence Act",
    "jurisdiction": "EU",
    "category": "ai_risk_safety",
    "version": "2024",
    "url": "https://eur-lex.europa.eu/eli/reg/2024/1689",
    "policies": [
        {
            "policy_id": "EU-AI-ACT-ART9",
            "regulation": "EU AI Act — Article 9 (Risk Management)",
            "severity": "BLOCKING",
            "description": "High-risk AI systems must have a risk management system",
            "evaluate": _eval_eu_ai_act_art9,
            "remediation": "Establish continuous risk management throughout lifecycle",
        },
        {
            "policy_id": "EU-AI-ACT-ART10",
            "regulation": "EU AI Act — Article 10 (Data Governance)",
            "severity": "CRITICAL",
            "description": "Training, validation, and testing data must be governed",
            "evaluate": _eval_eu_ai_act_art10,
            "remediation": "Implement data governance for all datasets",
        },
        {
            "policy_id": "EU-AI-ACT-ART12",
            "regulation": "EU AI Act — Article 12 (Record-Keeping)",
            "severity": "CRITICAL",
            "description": "Automatic event logging must be maintained",
            "evaluate": _eval_eu_ai_act_art12,
            "remediation": "Enable automatic logging of all system events",
        },
        {
            "policy_id": "EU-AI-ACT-ART14",
            "regulation": "EU AI Act — Article 14 (Human Oversight)",
            "severity": "BLOCKING",
            "description": "Human oversight must be enabled for high-risk systems",
            "evaluate": _eval_eu_ai_act_art14,
            "remediation": "Implement human-in-the-loop or human-on-the-loop oversight",
        },
        {
            "policy_id": "EU-AI-ACT-ART17",
            "regulation": "EU AI Act — Article 17 (Quality Management)",
            "severity": "CRITICAL",
            "description": "Quality management system must be in place",
            "evaluate": _eval_eu_ai_act_art17,
            "remediation": "Establish QMS covering risk, data, records, and monitoring",
        },
    ],
}


# ---- 3. ISO 42001 ----

def _eval_iso42001_annex_a2(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.2: AI policy and governance."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "ISO42001-A2-1", "CRITICAL",
            "No documented AI management policy covering risk assessment",
            "Establish AI policy per Annex A.2: define objectives, scope, and "
            "risk criteria for the AI management system",
        ))
    return violations


def _eval_iso42001_annex_a5(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.5: Data for AI systems."""
    violations = []
    if not ctx.get("has_data_governance"):
        violations.append(_violation(
            "ISO42001-A5-1", "CRITICAL",
            "No data management practices for AI system lifecycle",
            "Implement Annex A.5 data controls: establish processes for data "
            "acquisition, quality, labeling, and provenance tracking",
        ))
    if not ctx.get("has_data_provenance"):
        violations.append(_violation(
            "ISO42001-A5-2", "WARNING",
            "Data provenance not tracked for AI training data",
            "Per Annex A.5: maintain data provenance records including source, "
            "transformations, and quality assessments",
        ))
    return violations


def _eval_iso42001_annex_a6(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.6: AI system lifecycle."""
    violations = []
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "ISO42001-A6-1", "CRITICAL",
            "No monitoring and logging for AI system in operation",
            "Implement Annex A.6 monitoring: establish continuous monitoring, "
            "logging, and performance tracking for deployed AI systems",
        ))
    if not ctx.get("has_change_management"):
        violations.append(_violation(
            "ISO42001-A6-2", "WARNING",
            "No change management process for AI system updates",
            "Per Annex A.6: define change management procedures for model updates, "
            "retraining, and configuration changes",
        ))
    return violations


def _eval_iso42001_annex_a8(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.8: AI system impact assessment."""
    violations = []
    if not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "ISO42001-A8-1", "CRITICAL",
            "No impact assessment conducted for AI system",
            "Conduct Annex A.8 impact assessment: evaluate potential impacts on "
            "individuals, groups, and society including fairness and bias",
        ))
    return violations


ISO_42001: Framework = {
    "framework_id": "ISO_42001",
    "name": "ISO/IEC 42001 AI Management System",
    "jurisdiction": "INTERNATIONAL",
    "category": "ai_risk_safety",
    "version": "2023",
    "url": "https://www.iso.org/standard/81230.html",
    "policies": [
        {
            "policy_id": "ISO42001-A2",
            "regulation": "ISO 42001 — Annex A.2 (AI Policy)",
            "severity": "CRITICAL",
            "description": "AI management policy must be established and maintained",
            "evaluate": _eval_iso42001_annex_a2,
            "remediation": "Define AI policy with objectives, scope, and risk criteria",
        },
        {
            "policy_id": "ISO42001-A5",
            "regulation": "ISO 42001 — Annex A.5 (Data for AI)",
            "severity": "CRITICAL",
            "description": "Data management must cover acquisition, quality, and provenance",
            "evaluate": _eval_iso42001_annex_a5,
            "remediation": "Establish data governance for the full AI data lifecycle",
        },
        {
            "policy_id": "ISO42001-A6",
            "regulation": "ISO 42001 — Annex A.6 (AI Lifecycle)",
            "severity": "CRITICAL",
            "description": "AI system lifecycle must include monitoring and change management",
            "evaluate": _eval_iso42001_annex_a6,
            "remediation": "Implement monitoring, logging, and change management",
        },
        {
            "policy_id": "ISO42001-A8",
            "regulation": "ISO 42001 — Annex A.8 (Impact Assessment)",
            "severity": "CRITICAL",
            "description": "AI impact assessments must be conducted",
            "evaluate": _eval_iso42001_annex_a8,
            "remediation": "Conduct impact assessment covering fairness and societal effects",
        },
    ],
}


# ---- 4. MITRE ATLAS ----

def _eval_atlas_reconnaissance(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AML.T0000: ML model reconnaissance detection."""
    violations = []
    if not ctx.get("has_model_access_controls"):
        violations.append(_violation(
            "ATLAS-T0000-1", "CRITICAL",
            "No access controls to prevent ML model reconnaissance",
            "Implement AML.T0000 mitigations: restrict model API access, "
            "implement rate limiting, and monitor for enumeration patterns",
        ))
    return violations


def _eval_atlas_evasion(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AML.T0015: Adversarial input evasion detection."""
    violations = []
    if not ctx.get("has_input_validation"):
        violations.append(_violation(
            "ATLAS-T0015-1", "CRITICAL",
            "No input validation to detect adversarial evasion attacks",
            "Implement AML.T0015 mitigations: deploy input validation, "
            "adversarial example detection, and input preprocessing defenses",
        ))
    if not ctx.get("has_adversarial_testing"):
        violations.append(_violation(
            "ATLAS-T0015-2", "WARNING",
            "No adversarial robustness testing performed",
            "Conduct adversarial testing per ATLAS: test with known attack "
            "techniques (FGSM, PGD, C&W) and document resilience metrics",
        ))
    return violations


def _eval_atlas_poisoning(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AML.T0020: Data poisoning detection."""
    violations = []
    if not ctx.get("has_data_provenance"):
        violations.append(_violation(
            "ATLAS-T0020-1", "CRITICAL",
            "No data provenance tracking to detect training data poisoning",
            "Implement AML.T0020 mitigations: verify training data integrity, "
            "implement data provenance, and scan for anomalous samples",
        ))
    return violations


def _eval_atlas_exfiltration(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AML.T0024: Model theft / exfiltration."""
    violations = []
    if not ctx.get("has_model_access_controls"):
        violations.append(_violation(
            "ATLAS-T0024-1", "CRITICAL",
            "No protections against model theft or weight exfiltration",
            "Implement AML.T0024 mitigations: encrypt model artifacts, restrict "
            "API query rates, and watermark model outputs",
        ))
    return violations


MITRE_ATLAS: Framework = {
    "framework_id": "MITRE_ATLAS",
    "name": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
    "jurisdiction": "INTERNATIONAL",
    "category": "ai_risk_safety",
    "version": "4.0",
    "url": "https://atlas.mitre.org",
    "policies": [
        {
            "policy_id": "ATLAS-RECON",
            "regulation": "MITRE ATLAS — AML.T0000 (ML Model Reconnaissance)",
            "severity": "CRITICAL",
            "description": "Access controls must prevent ML model enumeration and reconnaissance",
            "evaluate": _eval_atlas_reconnaissance,
            "remediation": "Implement API access controls and query monitoring",
        },
        {
            "policy_id": "ATLAS-EVASION",
            "regulation": "MITRE ATLAS — AML.T0015 (Evasion via Adversarial Inputs)",
            "severity": "CRITICAL",
            "description": "Input validation must detect adversarial evasion attempts",
            "evaluate": _eval_atlas_evasion,
            "remediation": "Deploy input validation and adversarial detection",
        },
        {
            "policy_id": "ATLAS-POISONING",
            "regulation": "MITRE ATLAS — AML.T0020 (Data Poisoning)",
            "severity": "CRITICAL",
            "description": "Training data integrity must be verified and provenance tracked",
            "evaluate": _eval_atlas_poisoning,
            "remediation": "Implement data provenance and integrity verification",
        },
        {
            "policy_id": "ATLAS-EXFIL",
            "regulation": "MITRE ATLAS — AML.T0024 (Exfiltration via ML Model)",
            "severity": "CRITICAL",
            "description": "Model artifacts must be protected against theft and exfiltration",
            "evaluate": _eval_atlas_exfiltration,
            "remediation": "Encrypt model artifacts and restrict query access",
        },
    ],
}


# ---- 5. OWASP AI Top 10 ----

def _eval_owasp_ai_injection(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AI01: Prompt Injection."""
    violations = []
    if not ctx.get("has_input_validation"):
        violations.append(_violation(
            "OWASP-AI01-1", "BLOCKING",
            "No input validation to prevent prompt injection attacks",
            "Implement AI01 mitigations: input sanitization, prompt hardening, "
            "output validation, and privilege separation for LLM components",
        ))
    return violations


def _eval_owasp_ai_data_poisoning(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AI03: Training Data Poisoning."""
    violations = []
    if not ctx.get("has_data_provenance"):
        violations.append(_violation(
            "OWASP-AI03-1", "CRITICAL",
            "No safeguards against training data poisoning",
            "Implement AI03 mitigations: validate training data sources, implement "
            "anomaly detection on training datasets, and maintain data provenance",
        ))
    return violations


def _eval_owasp_ai_model_theft(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AI06: Model Theft."""
    violations = []
    if not ctx.get("has_model_access_controls"):
        violations.append(_violation(
            "OWASP-AI06-1", "CRITICAL",
            "No access controls protecting model intellectual property",
            "Implement AI06 mitigations: restrict model access, implement rate "
            "limiting on inference APIs, and monitor for extraction attempts",
        ))
    return violations


def _eval_owasp_ai_sensitive_disclosure(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AI07: Sensitive Information Disclosure."""
    violations = []
    if ctx.get("pii_detected"):
        violations.append(_violation(
            "OWASP-AI07-1", "BLOCKING",
            "PII detected in AI system output — sensitive information disclosure risk",
            "Implement AI07 mitigations: output filtering, PII scrubbing, "
            "differential privacy, and data sanitization in training data",
        ))
    if not ctx.get("has_output_filtering"):
        violations.append(_violation(
            "OWASP-AI07-2", "WARNING",
            "No output filtering to prevent sensitive data leakage",
            "Deploy output filtering per AI07: scan responses for PII, credentials, "
            "and proprietary data before returning to users",
        ))
    return violations


OWASP_AI_TOP_10: Framework = {
    "framework_id": "OWASP_AI_TOP_10",
    "name": "OWASP AI Security Top 10",
    "jurisdiction": "INTERNATIONAL",
    "category": "ai_risk_safety",
    "version": "2025",
    "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "policies": [
        {
            "policy_id": "OWASP-AI01",
            "regulation": "OWASP AI Top 10 — AI01 (Prompt Injection)",
            "severity": "BLOCKING",
            "description": "Systems must be protected against prompt injection attacks",
            "evaluate": _eval_owasp_ai_injection,
            "remediation": "Implement input validation, prompt hardening, output filtering",
        },
        {
            "policy_id": "OWASP-AI03",
            "regulation": "OWASP AI Top 10 — AI03 (Training Data Poisoning)",
            "severity": "CRITICAL",
            "description": "Training data must be protected against poisoning",
            "evaluate": _eval_owasp_ai_data_poisoning,
            "remediation": "Validate data sources and implement anomaly detection",
        },
        {
            "policy_id": "OWASP-AI06",
            "regulation": "OWASP AI Top 10 — AI06 (Model Theft)",
            "severity": "CRITICAL",
            "description": "Model intellectual property must be protected",
            "evaluate": _eval_owasp_ai_model_theft,
            "remediation": "Restrict model access and monitor for extraction",
        },
        {
            "policy_id": "OWASP-AI07",
            "regulation": "OWASP AI Top 10 — AI07 (Sensitive Information Disclosure)",
            "severity": "BLOCKING",
            "description": "AI outputs must not disclose sensitive or personal information",
            "evaluate": _eval_owasp_ai_sensitive_disclosure,
            "remediation": "Implement output filtering and PII scrubbing",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2 — REGIONAL REGULATIONS
# ═══════════════════════════════════════════════════════════════════════════


# ---- 6. Singapore AI Governance ----

def _eval_sg_pdpa_consent(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """PDPA: Consent and purpose limitation."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_consent_mechanism"):
        violations.append(_violation(
            "SG-PDPA-1", "BLOCKING",
            "Personal data processed without consent mechanism (PDPA Section 13)",
            "Implement PDPA Section 13: obtain consent before collecting, using, "
            "or disclosing personal data; document purpose of collection",
        ))
    return violations


def _eval_sg_model_governance(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Model AI Governance Framework: internal governance."""
    violations = []
    if not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "SG-MGF-1", "CRITICAL",
            "No human oversight per Singapore Model AI Governance Framework",
            "Implement Section 2.2: establish human oversight with clear accountability "
            "for AI-augmented decision-making",
        ))
    if not ctx.get("is_explainable"):
        violations.append(_violation(
            "SG-MGF-2", "WARNING",
            "AI system lacks explainability per Singapore governance framework",
            "Per Section 4: implement algorithmic explainability appropriate to the "
            "risk level and stakeholder needs",
        ))
    return violations


def _eval_sg_accountability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Model Governance: risk assessment and accountability."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "SG-MGF-3", "CRITICAL",
            "No risk assessment per Singapore Model AI Governance Framework",
            "Implement Section 1: conduct risk assessment including probability "
            "and severity of harm from AI system decisions",
        ))
    return violations


SINGAPORE_AI_GOV: Framework = {
    "framework_id": "SINGAPORE_AI_GOV",
    "name": "Singapore AI Governance Framework (PDPA + Model Governance)",
    "jurisdiction": "SG",
    "category": "regional_regulations",
    "version": "2.0",
    "url": "https://www.pdpc.gov.sg/help-and-resources/2020/01/model-ai-governance-framework",
    "policies": [
        {
            "policy_id": "SG-PDPA-CONSENT",
            "regulation": "PDPA — Section 13 (Consent Obligation)",
            "severity": "BLOCKING",
            "description": "Personal data requires consent before collection and processing",
            "evaluate": _eval_sg_pdpa_consent,
            "remediation": "Obtain and document consent before processing personal data",
        },
        {
            "policy_id": "SG-MGF-OVERSIGHT",
            "regulation": "Model AI Governance Framework — Section 2 (Human Oversight)",
            "severity": "CRITICAL",
            "description": "Human oversight and explainability must be implemented",
            "evaluate": _eval_sg_model_governance,
            "remediation": "Establish human oversight and algorithmic explainability",
        },
        {
            "policy_id": "SG-MGF-ACCOUNTABILITY",
            "regulation": "Model AI Governance Framework — Section 1 (Risk Assessment)",
            "severity": "CRITICAL",
            "description": "Risk assessment must be conducted for AI systems",
            "evaluate": _eval_sg_accountability,
            "remediation": "Conduct probability and severity assessment for AI harms",
        },
    ],
}


# ---- 7. UK AI Act (Pro-Innovation) ----

def _eval_uk_safety(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Safety principle: AI systems must be safe."""
    violations = []
    if not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "UK-AI-SAFETY-1", "CRITICAL",
            "No safety testing per UK pro-innovation AI regulation",
            "Implement safety principle: conduct testing to ensure AI system "
            "functions safely within intended parameters",
        ))
    if ctx.get("used_in_critical_infrastructure") and not ctx.get("has_incident_response"):
        violations.append(_violation(
            "UK-AI-SAFETY-2", "BLOCKING",
            "Critical infrastructure AI lacks incident response plan",
            "Establish incident response procedures for critical AI systems",
        ))
    return violations


def _eval_uk_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Transparency principle: appropriate transparency and explainability."""
    violations = []
    if not ctx.get("is_explainable"):
        violations.append(_violation(
            "UK-AI-TRANSPARENCY-1", "WARNING",
            "AI system lacks explainability per UK transparency principle",
            "Implement appropriate transparency: ensure AI decisions can be "
            "explained to affected parties in understandable terms",
        ))
    return violations


def _eval_uk_fairness(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Fairness principle: AI must not discriminate unlawfully."""
    violations = []
    if not ctx.get("has_bias_testing"):
        violations.append(_violation(
            "UK-AI-FAIRNESS-1", "CRITICAL",
            "No bias testing per UK fairness principle",
            "Conduct bias testing per Equality Act 2010 requirements: assess "
            "for discriminatory outcomes across protected characteristics",
        ))
    return violations


def _eval_uk_accountability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Accountability principle: clear lines of responsibility."""
    violations = []
    if not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "UK-AI-ACCOUNTABILITY-1", "CRITICAL",
            "No accountability mechanism for AI decisions",
            "Establish clear responsibility: designate accountable persons "
            "for AI system outputs and define escalation procedures",
        ))
    return violations


UK_AI_ACT: Framework = {
    "framework_id": "UK_AI_ACT",
    "name": "UK AI Regulation (Pro-Innovation Approach)",
    "jurisdiction": "UK",
    "category": "regional_regulations",
    "version": "2024",
    "url": "https://www.gov.uk/government/publications/ai-regulation-a-pro-innovation-approach",
    "policies": [
        {
            "policy_id": "UK-AI-SAFETY",
            "regulation": "UK AI — Safety Principle",
            "severity": "CRITICAL",
            "description": "AI systems must be safe and have incident response for critical use",
            "evaluate": _eval_uk_safety,
            "remediation": "Conduct safety testing and establish incident response",
        },
        {
            "policy_id": "UK-AI-TRANSPARENCY",
            "regulation": "UK AI — Transparency Principle",
            "severity": "WARNING",
            "description": "AI systems must be appropriately transparent and explainable",
            "evaluate": _eval_uk_transparency,
            "remediation": "Implement explainability appropriate to use case",
        },
        {
            "policy_id": "UK-AI-FAIRNESS",
            "regulation": "UK AI — Fairness Principle",
            "severity": "CRITICAL",
            "description": "AI must not produce unlawfully discriminatory outcomes",
            "evaluate": _eval_uk_fairness,
            "remediation": "Conduct bias testing across protected characteristics",
        },
        {
            "policy_id": "UK-AI-ACCOUNTABILITY",
            "regulation": "UK AI — Accountability Principle",
            "severity": "CRITICAL",
            "description": "Clear accountability must exist for AI system decisions",
            "evaluate": _eval_uk_accountability,
            "remediation": "Designate accountable persons and escalation procedures",
        },
    ],
}


# ---- 8. Canada AIDA ----

def _eval_aida_risk_assessment(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AIDA Section 7: Assessment of AI system risk levels."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "AIDA-S7-1", "CRITICAL",
            "No risk assessment per AIDA Section 7",
            "Conduct AIDA Section 7 assessment: determine whether system is a "
            "high-impact system based on prescribed criteria",
        ))
    return violations


def _eval_aida_mitigation(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AIDA Section 8: Mitigation measures for high-impact systems."""
    violations = []
    risk_level = ctx.get("risk_level", "").lower()
    if risk_level in ("high", "critical"):
        if not ctx.get("has_bias_testing"):
            violations.append(_violation(
                "AIDA-S8-1", "BLOCKING",
                "High-impact AI system lacks bias mitigation per AIDA Section 8",
                "Implement AIDA Section 8: establish measures to mitigate risks "
                "of harm and biased output for high-impact systems",
            ))
        if not ctx.get("has_human_oversight"):
            violations.append(_violation(
                "AIDA-S8-2", "CRITICAL",
                "High-impact AI system lacks human oversight per AIDA",
                "Establish human oversight mechanisms as required for high-impact systems",
            ))
    return violations


def _eval_aida_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """AIDA Section 10: Transparency obligations."""
    violations = []
    if ctx.get("makes_autonomous_decisions") and not ctx.get("is_explainable"):
        violations.append(_violation(
            "AIDA-S10-1", "CRITICAL",
            "Autonomous decision system not explainable per AIDA Section 10",
            "Implement AIDA Section 10: provide plain-language description of "
            "system, its capabilities, and how decisions are made",
        ))
    return violations


CANADA_AIDA: Framework = {
    "framework_id": "CANADA_AIDA",
    "name": "Canada Artificial Intelligence and Data Act (AIDA)",
    "jurisdiction": "CA",
    "category": "regional_regulations",
    "version": "2023",
    "url": "https://ised-isde.canada.ca/site/innovation-better-canada/en/artificial-intelligence-and-data-act",
    "policies": [
        {
            "policy_id": "AIDA-RISK",
            "regulation": "AIDA — Section 7 (Risk Assessment)",
            "severity": "CRITICAL",
            "description": "AI systems must be assessed for risk level",
            "evaluate": _eval_aida_risk_assessment,
            "remediation": "Determine high-impact status per prescribed criteria",
        },
        {
            "policy_id": "AIDA-MITIGATION",
            "regulation": "AIDA — Section 8 (Mitigation Measures)",
            "severity": "BLOCKING",
            "description": "High-impact systems must have bias and risk mitigation",
            "evaluate": _eval_aida_mitigation,
            "remediation": "Implement bias testing and human oversight for high-impact systems",
        },
        {
            "policy_id": "AIDA-TRANSPARENCY",
            "regulation": "AIDA — Section 10 (Transparency)",
            "severity": "CRITICAL",
            "description": "Autonomous decision systems must be transparent and explainable",
            "evaluate": _eval_aida_transparency,
            "remediation": "Provide plain-language explanation of AI capabilities",
        },
    ],
}


# ---- 9. China AI Regulations ----

def _eval_china_algorithmic(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Algorithmic Recommendation Management Provisions."""
    violations = []
    if not ctx.get("algorithmic_transparency"):
        violations.append(_violation(
            "CN-ALGO-1", "CRITICAL",
            "No algorithmic transparency per China Algorithmic Recommendation Provisions",
            "Implement Article 4: provide algorithm transparency, including "
            "notification of algorithmic recommendation usage and opt-out mechanism",
        ))
    if not ctx.get("has_opt_out"):
        violations.append(_violation(
            "CN-ALGO-2", "BLOCKING",
            "No user opt-out mechanism for algorithmic recommendations",
            "Per Article 17: provide users ability to opt out of algorithmic "
            "recommendations and disable personalized profiles",
        ))
    return violations


def _eval_china_deepfake(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Deep Synthesis Provisions (deepfake regulation)."""
    violations = []
    model_type = ctx.get("model_type", "").lower()
    if model_type in ("generative", "diffusion", "gan", "image_generation", "video_generation"):
        if not ctx.get("deepfake_detection_enabled"):
            violations.append(_violation(
                "CN-DEEP-1", "BLOCKING",
                "Generative AI lacks deepfake labeling per Deep Synthesis Provisions",
                "Implement Article 7: add visible labels to AI-generated content "
                "and maintain logs of synthesis activities",
            ))
    return violations


def _eval_china_generative(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Interim Measures for Generative AI (July 2023)."""
    violations = []
    if not ctx.get("has_data_governance"):
        violations.append(_violation(
            "CN-GEN-1", "CRITICAL",
            "No data governance per China Generative AI Measures",
            "Implement Article 7: ensure training data legality, implement "
            "data quality controls, and respect intellectual property rights",
        ))
    if not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "CN-GEN-2", "BLOCKING",
            "No safety assessment per China Generative AI Measures",
            "Per Article 17: conduct safety assessment before public release "
            "and file with the Cyberspace Administration of China",
        ))
    return violations


CHINA_AI_REGS: Framework = {
    "framework_id": "CHINA_AI_REGS",
    "name": "China AI Regulations (Algorithmic + Deepfake + Generative AI)",
    "jurisdiction": "CN",
    "category": "regional_regulations",
    "version": "2023",
    "url": "http://www.cac.gov.cn",
    "policies": [
        {
            "policy_id": "CN-ALGO",
            "regulation": "Algorithmic Recommendation Management Provisions (2022)",
            "severity": "BLOCKING",
            "description": "Algorithmic recommendations must be transparent with opt-out",
            "evaluate": _eval_china_algorithmic,
            "remediation": "Implement transparency notices and user opt-out",
        },
        {
            "policy_id": "CN-DEEPFAKE",
            "regulation": "Deep Synthesis Provisions (2023)",
            "severity": "BLOCKING",
            "description": "AI-generated content must be labeled and logged",
            "evaluate": _eval_china_deepfake,
            "remediation": "Add visible labels to generated content and log synthesis",
        },
        {
            "policy_id": "CN-GENERATIVE",
            "regulation": "Interim Measures for Generative AI (2023)",
            "severity": "BLOCKING",
            "description": "Generative AI must undergo safety assessment before release",
            "evaluate": _eval_china_generative,
            "remediation": "Conduct safety assessment and ensure data governance",
        },
    ],
}


# ---- 10. US Executive Order on AI (EO 14110) ----

def _eval_eo14110_safety_testing(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 4.2: Safety testing and red-teaming."""
    violations = []
    if not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "EO14110-S4.2-1", "CRITICAL",
            "No safety testing per EO 14110 Section 4.2",
            "Implement Section 4.2: conduct pre-deployment safety testing including "
            "red-teaming for dual-use foundation models",
        ))
    if not ctx.get("has_red_teaming"):
        violations.append(_violation(
            "EO14110-S4.2-2", "CRITICAL",
            "No red-teaming conducted per EO 14110",
            "Per Section 4.2: perform red-team testing to identify vulnerabilities, "
            "misuse vectors, and potential for catastrophic risk",
        ))
    return violations


def _eval_eo14110_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 4.5: AI content authentication and watermarking."""
    violations = []
    model_type = ctx.get("model_type", "").lower()
    if model_type in ("generative", "diffusion", "llm", "foundation"):
        if not ctx.get("has_transparency_report"):
            violations.append(_violation(
                "EO14110-S4.5-1", "WARNING",
                "No AI content authentication per EO 14110 Section 4.5",
                "Implement Section 4.5: establish standards for authenticating "
                "AI-generated content and detecting synthetic media",
            ))
    return violations


def _eval_eo14110_privacy(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 9: Privacy protections in AI."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "EO14110-S9-1", "CRITICAL",
            "No privacy impact assessment for AI handling personal data per EO 14110",
            "Per Section 9: evaluate AI system privacy risks and mitigate "
            "potential for surveillance and data misuse",
        ))
    return violations


US_EO_14110: Framework = {
    "framework_id": "US_EO_14110",
    "name": "US Executive Order on Safe, Secure, and Trustworthy AI (EO 14110)",
    "jurisdiction": "US",
    "category": "regional_regulations",
    "version": "2023",
    "url": "https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/",
    "policies": [
        {
            "policy_id": "EO14110-SAFETY",
            "regulation": "EO 14110 — Section 4.2 (Safety Testing & Red-Teaming)",
            "severity": "CRITICAL",
            "description": "AI systems must undergo safety testing and red-teaming",
            "evaluate": _eval_eo14110_safety_testing,
            "remediation": "Conduct pre-deployment safety testing and red-team exercises",
        },
        {
            "policy_id": "EO14110-TRANSPARENCY",
            "regulation": "EO 14110 — Section 4.5 (Content Authentication)",
            "severity": "WARNING",
            "description": "Generative AI must support content authentication",
            "evaluate": _eval_eo14110_transparency,
            "remediation": "Implement content authentication and watermarking",
        },
        {
            "policy_id": "EO14110-PRIVACY",
            "regulation": "EO 14110 — Section 9 (Privacy)",
            "severity": "CRITICAL",
            "description": "AI handling personal data must have privacy impact assessment",
            "evaluate": _eval_eo14110_privacy,
            "remediation": "Conduct privacy impact assessment for AI systems",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3 — DATA PRIVACY
# ═══════════════════════════════════════════════════════════════════════════


# ---- 11. GDPR ----

def _eval_gdpr_art22(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 22: Automated individual decision-making."""
    violations = []
    if ctx.get("makes_autonomous_decisions") and ctx.get("handles_personal_data"):
        if not ctx.get("has_human_oversight"):
            violations.append(_violation(
                "GDPR-ART22-1", "BLOCKING",
                "Automated decision-making on personal data without human oversight "
                "violates GDPR Article 22(1)",
                "Implement Article 22(3): provide meaningful human intervention, "
                "right to contest, and ability to obtain explanation of the decision",
            ))
        if not ctx.get("has_opt_out"):
            violations.append(_violation(
                "GDPR-ART22-2", "BLOCKING",
                "No opt-out from automated decision-making (GDPR Article 22)",
                "Per Article 22(1): data subjects have right not to be subject to "
                "solely automated decisions with legal or significant effects",
            ))
    return violations


def _eval_gdpr_art35(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 35: Data Protection Impact Assessment (DPIA)."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "GDPR-ART35-1", "BLOCKING",
            "No DPIA conducted for AI processing personal data (GDPR Article 35)",
            "Conduct Article 35 DPIA: assess necessity, proportionality, and risks "
            "of personal data processing; document measures to address risks",
        ))
    return violations


def _eval_gdpr_data_minimization(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 5(1)(c): Data minimization principle."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("data_minimization"):
        violations.append(_violation(
            "GDPR-ART5C-1", "CRITICAL",
            "Data minimization principle not applied (GDPR Article 5(1)(c))",
            "Implement Article 5(1)(c): ensure personal data is adequate, relevant, "
            "and limited to what is necessary for the stated purpose",
        ))
    return violations


def _eval_gdpr_consent(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Article 6/7: Lawful basis and consent."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_consent_mechanism"):
        violations.append(_violation(
            "GDPR-ART6-1", "BLOCKING",
            "No lawful basis for processing personal data (GDPR Article 6)",
            "Establish Article 6 lawful basis: obtain explicit consent per Article 7, "
            "or document alternative legal basis (legitimate interest, contract, etc.)",
        ))
    return violations


GDPR: Framework = {
    "framework_id": "GDPR",
    "name": "General Data Protection Regulation",
    "jurisdiction": "EU",
    "category": "data_privacy",
    "version": "2016/679",
    "url": "https://eur-lex.europa.eu/eli/reg/2016/679",
    "policies": [
        {
            "policy_id": "GDPR-ART22",
            "regulation": "GDPR — Article 22 (Automated Decision-Making)",
            "severity": "BLOCKING",
            "description": "Automated decisions with legal effects require human oversight and opt-out",
            "evaluate": _eval_gdpr_art22,
            "remediation": "Implement human intervention, contestation rights, and opt-out",
        },
        {
            "policy_id": "GDPR-ART35",
            "regulation": "GDPR — Article 35 (DPIA)",
            "severity": "BLOCKING",
            "description": "Data Protection Impact Assessment required for high-risk processing",
            "evaluate": _eval_gdpr_art35,
            "remediation": "Conduct and document DPIA before processing",
        },
        {
            "policy_id": "GDPR-ART5C",
            "regulation": "GDPR — Article 5(1)(c) (Data Minimization)",
            "severity": "CRITICAL",
            "description": "Personal data must be limited to what is necessary",
            "evaluate": _eval_gdpr_data_minimization,
            "remediation": "Implement data minimization in collection and processing",
        },
        {
            "policy_id": "GDPR-ART6",
            "regulation": "GDPR — Article 6/7 (Lawful Basis & Consent)",
            "severity": "BLOCKING",
            "description": "Processing must have lawful basis with valid consent",
            "evaluate": _eval_gdpr_consent,
            "remediation": "Establish and document lawful basis for processing",
        },
    ],
}


# ---- 12. CCPA ----

def _eval_ccpa_consumer_rights(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 1798.100: Consumer right to know."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_transparency_report"):
        violations.append(_violation(
            "CCPA-1798.100-1", "CRITICAL",
            "No transparency about personal information collection (CCPA 1798.100)",
            "Implement Section 1798.100: disclose categories of personal information "
            "collected, purposes, and categories of third parties shared with",
        ))
    return violations


def _eval_ccpa_opt_out(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 1798.120: Right to opt out of sale/sharing."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_opt_out"):
        violations.append(_violation(
            "CCPA-1798.120-1", "BLOCKING",
            "No opt-out mechanism for data sharing (CCPA 1798.120)",
            "Implement Section 1798.120: provide 'Do Not Sell or Share My Personal "
            "Information' mechanism and honor opt-out requests",
        ))
    return violations


def _eval_ccpa_data_minimization(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Section 1798.100(c): Data minimization (CPRA amendment)."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("data_minimization"):
        violations.append(_violation(
            "CCPA-1798.100C-1", "CRITICAL",
            "Data minimization not applied (CCPA/CPRA 1798.100(c))",
            "Implement Section 1798.100(c): limit collection and use of personal "
            "information to what is reasonably necessary and proportionate",
        ))
    return violations


CCPA: Framework = {
    "framework_id": "CCPA",
    "name": "California Consumer Privacy Act (CCPA/CPRA)",
    "jurisdiction": "US-CA",
    "category": "data_privacy",
    "version": "2023",
    "url": "https://oag.ca.gov/privacy/ccpa",
    "policies": [
        {
            "policy_id": "CCPA-KNOW",
            "regulation": "CCPA — Section 1798.100 (Right to Know)",
            "severity": "CRITICAL",
            "description": "Consumers must be informed about personal data collection practices",
            "evaluate": _eval_ccpa_consumer_rights,
            "remediation": "Disclose data collection categories, purposes, and third parties",
        },
        {
            "policy_id": "CCPA-OPTOUT",
            "regulation": "CCPA — Section 1798.120 (Right to Opt Out)",
            "severity": "BLOCKING",
            "description": "Consumers must have ability to opt out of data sale/sharing",
            "evaluate": _eval_ccpa_opt_out,
            "remediation": "Implement opt-out mechanism and honor requests",
        },
        {
            "policy_id": "CCPA-MINIMIZE",
            "regulation": "CCPA/CPRA — Section 1798.100(c) (Data Minimization)",
            "severity": "CRITICAL",
            "description": "Data collection must be reasonably necessary and proportionate",
            "evaluate": _eval_ccpa_data_minimization,
            "remediation": "Limit collection to what is necessary for stated purpose",
        },
    ],
}


# ---- 13. HIPAA ----

def _eval_hipaa_phi(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Privacy Rule: PHI protection."""
    violations = []
    data_types = ctx.get("data_types", [])
    has_health_data = any(
        dt in ("health", "medical", "phi", "healthcare", "clinical")
        for dt in (data_types if isinstance(data_types, list) else [data_types])
    )
    if has_health_data and not ctx.get("has_phi_protection"):
        violations.append(_violation(
            "HIPAA-PRIVACY-1", "BLOCKING",
            "Protected Health Information (PHI) lacks required safeguards",
            "Implement HIPAA Privacy Rule 45 CFR 164.502: apply minimum necessary "
            "standard, implement use and disclosure limitations for PHI",
        ))
    return violations


def _eval_hipaa_minimum_necessary(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """45 CFR 164.502(b): Minimum necessary standard."""
    violations = []
    data_types = ctx.get("data_types", [])
    has_health_data = any(
        dt in ("health", "medical", "phi", "healthcare", "clinical")
        for dt in (data_types if isinstance(data_types, list) else [data_types])
    )
    if has_health_data and not ctx.get("data_minimization"):
        violations.append(_violation(
            "HIPAA-MIN-1", "CRITICAL",
            "Minimum necessary standard not applied to PHI (45 CFR 164.502(b))",
            "Implement 45 CFR 164.502(b): limit PHI use, disclosure, and requests "
            "to the minimum necessary to accomplish the intended purpose",
        ))
    return violations


def _eval_hipaa_access_controls(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Security Rule 45 CFR 164.312(a): Access controls."""
    violations = []
    data_types = ctx.get("data_types", [])
    has_health_data = any(
        dt in ("health", "medical", "phi", "healthcare", "clinical")
        for dt in (data_types if isinstance(data_types, list) else [data_types])
    )
    if has_health_data:
        if not ctx.get("has_access_controls"):
            violations.append(_violation(
                "HIPAA-SEC-1", "BLOCKING",
                "No access controls for ePHI (45 CFR 164.312(a))",
                "Implement 45 CFR 164.312(a): unique user identification, "
                "emergency access procedure, automatic logoff, encryption",
            ))
        if not ctx.get("has_audit_trail"):
            violations.append(_violation(
                "HIPAA-SEC-2", "CRITICAL",
                "No audit trail for ePHI access (45 CFR 164.312(b))",
                "Implement 45 CFR 164.312(b): record and examine activity in "
                "systems containing or using ePHI",
            ))
    return violations


HIPAA: Framework = {
    "framework_id": "HIPAA",
    "name": "Health Insurance Portability and Accountability Act",
    "jurisdiction": "US",
    "category": "data_privacy",
    "version": "1996 (amended)",
    "url": "https://www.hhs.gov/hipaa/index.html",
    "policies": [
        {
            "policy_id": "HIPAA-PHI",
            "regulation": "HIPAA Privacy Rule — 45 CFR 164.502 (PHI Protection)",
            "severity": "BLOCKING",
            "description": "Protected Health Information must have required safeguards",
            "evaluate": _eval_hipaa_phi,
            "remediation": "Implement PHI safeguards and use/disclosure limitations",
        },
        {
            "policy_id": "HIPAA-MINIMUM",
            "regulation": "HIPAA — 45 CFR 164.502(b) (Minimum Necessary)",
            "severity": "CRITICAL",
            "description": "PHI access must be limited to minimum necessary",
            "evaluate": _eval_hipaa_minimum_necessary,
            "remediation": "Apply minimum necessary standard to all PHI operations",
        },
        {
            "policy_id": "HIPAA-ACCESS",
            "regulation": "HIPAA Security Rule — 45 CFR 164.312 (Access Controls)",
            "severity": "BLOCKING",
            "description": "ePHI must have technical access controls and audit trails",
            "evaluate": _eval_hipaa_access_controls,
            "remediation": "Implement access controls, encryption, and audit logging",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4 — SECURITY & INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════


# ---- 14. ISO 27001 ----

def _eval_iso27001_risk(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Clause 6.1.2: Information security risk assessment."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "ISO27001-6.1.2-1", "CRITICAL",
            "No information security risk assessment (ISO 27001 Clause 6.1.2)",
            "Implement Clause 6.1.2: define risk assessment process, identify "
            "risks to confidentiality, integrity, and availability of information",
        ))
    return violations


def _eval_iso27001_access(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.9: Access control."""
    violations = []
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "ISO27001-A9-1", "CRITICAL",
            "No access control policy (ISO 27001 Annex A.9)",
            "Implement Annex A.9.1: establish access control policy based on "
            "business and security requirements; implement least privilege",
        ))
    if not ctx.get("has_mfa"):
        violations.append(_violation(
            "ISO27001-A9-2", "WARNING",
            "Multi-factor authentication not implemented (ISO 27001 Annex A.9)",
            "Per Annex A.9.4: implement MFA for access to sensitive systems "
            "and information processing facilities",
        ))
    return violations


def _eval_iso27001_encryption(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.10: Cryptography."""
    violations = []
    if not ctx.get("has_encryption"):
        violations.append(_violation(
            "ISO27001-A10-1", "CRITICAL",
            "No encryption policy (ISO 27001 Annex A.10)",
            "Implement Annex A.10.1: develop cryptographic policy for data "
            "protection at rest and in transit",
        ))
    return violations


def _eval_iso27001_incident(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annex A.16: Information security incident management."""
    violations = []
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "ISO27001-A16-1", "CRITICAL",
            "No incident response procedures (ISO 27001 Annex A.16)",
            "Implement Annex A.16.1: establish incident management procedures "
            "including reporting, assessment, response, and lessons learned",
        ))
    return violations


ISO_27001: Framework = {
    "framework_id": "ISO_27001",
    "name": "ISO/IEC 27001 Information Security Management",
    "jurisdiction": "INTERNATIONAL",
    "category": "security_infrastructure",
    "version": "2022",
    "url": "https://www.iso.org/standard/27001",
    "policies": [
        {
            "policy_id": "ISO27001-RISK",
            "regulation": "ISO 27001 — Clause 6.1.2 (Risk Assessment)",
            "severity": "CRITICAL",
            "description": "Information security risk assessment must be performed",
            "evaluate": _eval_iso27001_risk,
            "remediation": "Conduct risk assessment for C/I/A of information assets",
        },
        {
            "policy_id": "ISO27001-ACCESS",
            "regulation": "ISO 27001 — Annex A.9 (Access Control)",
            "severity": "CRITICAL",
            "description": "Access control policy with least privilege must be implemented",
            "evaluate": _eval_iso27001_access,
            "remediation": "Implement access controls, MFA, and least privilege",
        },
        {
            "policy_id": "ISO27001-CRYPTO",
            "regulation": "ISO 27001 — Annex A.10 (Cryptography)",
            "severity": "CRITICAL",
            "description": "Cryptographic controls must protect data at rest and in transit",
            "evaluate": _eval_iso27001_encryption,
            "remediation": "Develop and implement cryptographic policy",
        },
        {
            "policy_id": "ISO27001-INCIDENT",
            "regulation": "ISO 27001 — Annex A.16 (Incident Management)",
            "severity": "CRITICAL",
            "description": "Incident management procedures must be established",
            "evaluate": _eval_iso27001_incident,
            "remediation": "Establish incident reporting, response, and review procedures",
        },
    ],
}


# ---- 15. NIST CSF ----

def _eval_nist_csf_identify(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """IDENTIFY: Asset management and risk assessment."""
    violations = []
    if not ctx.get("has_asset_inventory"):
        violations.append(_violation(
            "NIST-CSF-ID-1", "CRITICAL",
            "No asset inventory (NIST CSF ID.AM)",
            "Implement ID.AM: inventory physical devices, software platforms, "
            "data flows, and external information systems",
        ))
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "NIST-CSF-ID-2", "CRITICAL",
            "No cybersecurity risk assessment (NIST CSF ID.RA)",
            "Implement ID.RA: identify and document vulnerabilities, threats, "
            "likelihoods, and impacts to organizational assets",
        ))
    return violations


def _eval_nist_csf_protect(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """PROTECT: Safeguards to ensure delivery of critical services."""
    violations = []
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "NIST-CSF-PR-1", "CRITICAL",
            "No access controls (NIST CSF PR.AC)",
            "Implement PR.AC: manage identities and credentials, implement "
            "remote access controls and access permissions",
        ))
    if not ctx.get("has_encryption"):
        violations.append(_violation(
            "NIST-CSF-PR-2", "WARNING",
            "No data protection at rest/transit (NIST CSF PR.DS)",
            "Implement PR.DS: protect data at rest and in transit with "
            "appropriate cryptographic mechanisms",
        ))
    return violations


def _eval_nist_csf_detect(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DETECT: Activities to identify cybersecurity events."""
    violations = []
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "NIST-CSF-DE-1", "CRITICAL",
            "No security monitoring and logging (NIST CSF DE.CM)",
            "Implement DE.CM: monitor network, physical environment, personnel "
            "activity, and external service providers for anomalies",
        ))
    return violations


def _eval_nist_csf_respond_recover(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """RESPOND + RECOVER: Incident response and recovery planning."""
    violations = []
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "NIST-CSF-RS-1", "CRITICAL",
            "No incident response plan (NIST CSF RS.RP)",
            "Implement RS.RP: establish response plan executed during or after "
            "a detected cybersecurity incident",
        ))
    if not ctx.get("has_backup_recovery"):
        violations.append(_violation(
            "NIST-CSF-RC-1", "CRITICAL",
            "No recovery plan (NIST CSF RC.RP)",
            "Implement RC.RP: establish recovery plan executed during or after "
            "an incident to restore systems and assets",
        ))
    return violations


NIST_CSF: Framework = {
    "framework_id": "NIST_CSF",
    "name": "NIST Cybersecurity Framework",
    "jurisdiction": "US",
    "category": "security_infrastructure",
    "version": "2.0",
    "url": "https://www.nist.gov/cyberframework",
    "policies": [
        {
            "policy_id": "NIST-CSF-IDENTIFY",
            "regulation": "NIST CSF — IDENTIFY (ID.AM, ID.RA)",
            "severity": "CRITICAL",
            "description": "Assets must be inventoried and risks assessed",
            "evaluate": _eval_nist_csf_identify,
            "remediation": "Inventory assets and conduct risk assessment",
        },
        {
            "policy_id": "NIST-CSF-PROTECT",
            "regulation": "NIST CSF — PROTECT (PR.AC, PR.DS)",
            "severity": "CRITICAL",
            "description": "Access controls and data protection must be in place",
            "evaluate": _eval_nist_csf_protect,
            "remediation": "Implement access controls and encryption",
        },
        {
            "policy_id": "NIST-CSF-DETECT",
            "regulation": "NIST CSF — DETECT (DE.CM)",
            "severity": "CRITICAL",
            "description": "Security monitoring and anomaly detection must be active",
            "evaluate": _eval_nist_csf_detect,
            "remediation": "Enable security monitoring and logging",
        },
        {
            "policy_id": "NIST-CSF-RESPOND-RECOVER",
            "regulation": "NIST CSF — RESPOND/RECOVER (RS.RP, RC.RP)",
            "severity": "CRITICAL",
            "description": "Incident response and recovery plans must exist",
            "evaluate": _eval_nist_csf_respond_recover,
            "remediation": "Establish incident response and recovery plans",
        },
    ],
}


# ---- 16. Zero Trust Architecture ----

def _eval_zt_verify(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Never trust, always verify."""
    violations = []
    if not ctx.get("has_mfa"):
        violations.append(_violation(
            "ZTA-VERIFY-1", "CRITICAL",
            "No multi-factor authentication (Zero Trust: always verify)",
            "Implement Zero Trust verify principle: require MFA for all access "
            "requests regardless of network location",
        ))
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "ZTA-VERIFY-2", "CRITICAL",
            "No identity-based access controls (Zero Trust)",
            "Implement identity verification: authenticate and authorize every "
            "access request based on all available data points",
        ))
    return violations


def _eval_zt_least_privilege(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Least privilege access."""
    violations = []
    if ctx.get("makes_autonomous_decisions") and not ctx.get("has_access_controls"):
        violations.append(_violation(
            "ZTA-LP-1", "BLOCKING",
            "Autonomous system without least-privilege access controls",
            "Implement Zero Trust least privilege: limit AI system access to "
            "minimum resources needed; use just-in-time and just-enough-access",
        ))
    return violations


def _eval_zt_assume_breach(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Assume breach: minimize blast radius."""
    violations = []
    if not ctx.get("has_network_segmentation"):
        violations.append(_violation(
            "ZTA-BREACH-1", "WARNING",
            "No network segmentation (Zero Trust: assume breach)",
            "Implement micro-segmentation: segment access by network, user, "
            "device, and application to minimize blast radius",
        ))
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "ZTA-BREACH-2", "CRITICAL",
            "No continuous monitoring (Zero Trust: assume breach)",
            "Enable continuous monitoring: log all access, analyze for anomalies, "
            "and automate threat detection and response",
        ))
    return violations


ZERO_TRUST: Framework = {
    "framework_id": "ZERO_TRUST",
    "name": "Zero Trust Architecture",
    "jurisdiction": "INTERNATIONAL",
    "category": "security_infrastructure",
    "version": "NIST SP 800-207",
    "url": "https://csrc.nist.gov/pubs/sp/800/207/final",
    "policies": [
        {
            "policy_id": "ZTA-VERIFY",
            "regulation": "Zero Trust — Always Verify (NIST SP 800-207)",
            "severity": "CRITICAL",
            "description": "Every access request must be authenticated and authorized",
            "evaluate": _eval_zt_verify,
            "remediation": "Implement MFA and identity-based access controls",
        },
        {
            "policy_id": "ZTA-LEAST-PRIV",
            "regulation": "Zero Trust — Least Privilege Access",
            "severity": "BLOCKING",
            "description": "Access must be limited to minimum necessary resources",
            "evaluate": _eval_zt_least_privilege,
            "remediation": "Implement JIT/JEA access for autonomous systems",
        },
        {
            "policy_id": "ZTA-BREACH",
            "regulation": "Zero Trust — Assume Breach",
            "severity": "CRITICAL",
            "description": "Segmentation and monitoring must minimize breach impact",
            "evaluate": _eval_zt_assume_breach,
            "remediation": "Implement micro-segmentation and continuous monitoring",
        },
    ],
}


# ---- 17. CIS Controls ----

def _eval_cis_inventory(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CIS Control 1/2: Inventory of assets."""
    violations = []
    if not ctx.get("has_asset_inventory"):
        violations.append(_violation(
            "CIS-C1-1", "CRITICAL",
            "No enterprise asset inventory (CIS Control 1)",
            "Implement CIS Control 1: establish and maintain inventory of all "
            "enterprise assets including hardware, software, and data",
        ))
    return violations


def _eval_cis_access(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CIS Control 5/6: Account and access control management."""
    violations = []
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "CIS-C5-1", "CRITICAL",
            "No account management process (CIS Control 5)",
            "Implement CIS Control 5: manage credentials, establish and "
            "maintain process for granting/revoking access",
        ))
    if not ctx.get("has_mfa"):
        violations.append(_violation(
            "CIS-C6-1", "CRITICAL",
            "No MFA for administrative access (CIS Control 6)",
            "Implement CIS Control 6.3: require MFA for all administrative "
            "access and remote network access",
        ))
    return violations


def _eval_cis_vulnerability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CIS Control 7: Continuous vulnerability management."""
    violations = []
    if not ctx.get("has_vulnerability_scanning"):
        violations.append(_violation(
            "CIS-C7-1", "CRITICAL",
            "No vulnerability management process (CIS Control 7)",
            "Implement CIS Control 7: establish process to continuously assess, "
            "track, and remediate vulnerabilities across enterprise assets",
        ))
    return violations


def _eval_cis_logging(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CIS Control 8: Audit log management."""
    violations = []
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "CIS-C8-1", "CRITICAL",
            "No audit log management (CIS Control 8)",
            "Implement CIS Control 8: collect, alert, review, and retain audit "
            "logs of events that could help detect or recover from attacks",
        ))
    return violations


CIS_CONTROLS: Framework = {
    "framework_id": "CIS_CONTROLS",
    "name": "CIS Critical Security Controls",
    "jurisdiction": "INTERNATIONAL",
    "category": "security_infrastructure",
    "version": "8.0",
    "url": "https://www.cisecurity.org/controls",
    "policies": [
        {
            "policy_id": "CIS-INVENTORY",
            "regulation": "CIS Controls — Control 1/2 (Asset Inventory)",
            "severity": "CRITICAL",
            "description": "Enterprise assets must be inventoried and managed",
            "evaluate": _eval_cis_inventory,
            "remediation": "Establish and maintain asset inventory",
        },
        {
            "policy_id": "CIS-ACCESS",
            "regulation": "CIS Controls — Control 5/6 (Access Management)",
            "severity": "CRITICAL",
            "description": "Account management and MFA must be implemented",
            "evaluate": _eval_cis_access,
            "remediation": "Implement account management process and MFA",
        },
        {
            "policy_id": "CIS-VULN",
            "regulation": "CIS Controls — Control 7 (Vulnerability Management)",
            "severity": "CRITICAL",
            "description": "Vulnerabilities must be continuously assessed and remediated",
            "evaluate": _eval_cis_vulnerability,
            "remediation": "Establish continuous vulnerability management",
        },
        {
            "policy_id": "CIS-LOGGING",
            "regulation": "CIS Controls — Control 8 (Audit Log Management)",
            "severity": "CRITICAL",
            "description": "Audit logs must be collected, reviewed, and retained",
            "evaluate": _eval_cis_logging,
            "remediation": "Implement audit log collection and review",
        },
    ],
}


# ---- 18. SOC 2 ----

def _eval_soc2_security(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CC6: Logical and physical access controls."""
    violations = []
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "SOC2-CC6-1", "CRITICAL",
            "No logical access controls (SOC 2 CC6.1)",
            "Implement CC6.1: restrict logical access to information assets "
            "through access controls, authentication, and authorization",
        ))
    if not ctx.get("has_encryption"):
        violations.append(_violation(
            "SOC2-CC6-2", "CRITICAL",
            "No encryption for data protection (SOC 2 CC6.7)",
            "Implement CC6.7: restrict transmission, movement, and removal of "
            "information to authorized users using encryption",
        ))
    return violations


def _eval_soc2_availability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """A1: Additional criteria for availability."""
    violations = []
    if not ctx.get("has_backup_recovery"):
        violations.append(_violation(
            "SOC2-A1-1", "CRITICAL",
            "No backup and recovery plan (SOC 2 A1.2)",
            "Implement A1.2: maintain environmental protections, software, data "
            "backup, and recovery infrastructure for system availability",
        ))
    return violations


def _eval_soc2_processing_integrity(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """PI1: Processing integrity criteria."""
    violations = []
    if not ctx.get("has_input_validation"):
        violations.append(_violation(
            "SOC2-PI1-1", "WARNING",
            "No input validation for processing integrity (SOC 2 PI1.2)",
            "Implement PI1.2: validate inputs are complete, accurate, and "
            "authorized before system processing",
        ))
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "SOC2-PI1-2", "CRITICAL",
            "No processing logging for integrity verification (SOC 2 PI1.4)",
            "Implement PI1.4: record system processing and detect processing "
            "deviations to ensure output completeness and accuracy",
        ))
    return violations


def _eval_soc2_confidentiality(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """C1: Confidentiality commitments."""
    violations = []
    if ctx.get("handles_personal_data") and not ctx.get("has_access_controls"):
        violations.append(_violation(
            "SOC2-C1-1", "CRITICAL",
            "No confidentiality controls for sensitive data (SOC 2 C1.1)",
            "Implement C1.1: identify and maintain confidential information; "
            "restrict access based on classification and need-to-know",
        ))
    return violations


SOC_2: Framework = {
    "framework_id": "SOC_2",
    "name": "SOC 2 Trust Service Criteria",
    "jurisdiction": "US",
    "category": "security_infrastructure",
    "version": "2017 (with 2022 points of focus)",
    "url": "https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services",
    "policies": [
        {
            "policy_id": "SOC2-SECURITY",
            "regulation": "SOC 2 — CC6 (Logical & Physical Access)",
            "severity": "CRITICAL",
            "description": "Access controls and encryption must protect information assets",
            "evaluate": _eval_soc2_security,
            "remediation": "Implement access controls and encryption",
        },
        {
            "policy_id": "SOC2-AVAILABILITY",
            "regulation": "SOC 2 — A1 (Availability)",
            "severity": "CRITICAL",
            "description": "System availability must be maintained with backup and recovery",
            "evaluate": _eval_soc2_availability,
            "remediation": "Establish backup and recovery infrastructure",
        },
        {
            "policy_id": "SOC2-INTEGRITY",
            "regulation": "SOC 2 — PI1 (Processing Integrity)",
            "severity": "CRITICAL",
            "description": "System processing must be complete, accurate, and timely",
            "evaluate": _eval_soc2_processing_integrity,
            "remediation": "Implement input validation and processing logging",
        },
        {
            "policy_id": "SOC2-CONFIDENTIALITY",
            "regulation": "SOC 2 — C1 (Confidentiality)",
            "severity": "CRITICAL",
            "description": "Confidential information must be protected per commitments",
            "evaluate": _eval_soc2_confidentiality,
            "remediation": "Classify data and restrict access based on need-to-know",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5 — IT GOVERNANCE & RISK
# ═══════════════════════════════════════════════════════════════════════════


# ---- 19. COBIT ----

def _eval_cobit_governance(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """EDM01: Ensured governance framework setting and maintenance."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "COBIT-EDM01-1", "CRITICAL",
            "No IT governance framework with risk assessment (COBIT EDM01)",
            "Implement EDM01: establish governance framework that evaluates "
            "strategic alignment, risk optimization, and value delivery",
        ))
    return violations


def _eval_cobit_risk(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """APO12: Managed risk."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "COBIT-APO12-1", "CRITICAL",
            "No managed risk process (COBIT APO12)",
            "Implement APO12: continuously identify, assess, and reduce "
            "IT-related risk within defined tolerance levels",
        ))
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "COBIT-APO12-2", "WARNING",
            "No risk response plan (COBIT APO12.06)",
            "Per APO12.06: define and implement risk response actions to "
            "bring risk within acceptable limits",
        ))
    return violations


def _eval_cobit_monitoring(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """MEA01: Managed performance and conformance monitoring."""
    violations = []
    if not ctx.get("has_logging"):
        violations.append(_violation(
            "COBIT-MEA01-1", "CRITICAL",
            "No performance monitoring (COBIT MEA01)",
            "Implement MEA01: establish monitoring approach, set performance "
            "and conformance targets, and collect and process data",
        ))
    return violations


COBIT: Framework = {
    "framework_id": "COBIT",
    "name": "COBIT (Control Objectives for Information and Related Technologies)",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "2019",
    "url": "https://www.isaca.org/resources/cobit",
    "policies": [
        {
            "policy_id": "COBIT-GOVERNANCE",
            "regulation": "COBIT — EDM01 (Governance Framework)",
            "severity": "CRITICAL",
            "description": "IT governance framework must be established and maintained",
            "evaluate": _eval_cobit_governance,
            "remediation": "Establish governance framework with strategic alignment",
        },
        {
            "policy_id": "COBIT-RISK",
            "regulation": "COBIT — APO12 (Managed Risk)",
            "severity": "CRITICAL",
            "description": "IT risks must be continuously identified, assessed, and managed",
            "evaluate": _eval_cobit_risk,
            "remediation": "Implement continuous risk identification and response",
        },
        {
            "policy_id": "COBIT-MONITORING",
            "regulation": "COBIT — MEA01 (Performance Monitoring)",
            "severity": "CRITICAL",
            "description": "Performance and conformance must be monitored",
            "evaluate": _eval_cobit_monitoring,
            "remediation": "Establish monitoring targets and data collection",
        },
    ],
}


# ---- 20. ITIL ----

def _eval_itil_incident(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """ITIL Incident Management practice."""
    violations = []
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "ITIL-INC-1", "CRITICAL",
            "No incident management process (ITIL Incident Management)",
            "Implement ITIL Incident Management: define incident detection, "
            "logging, categorization, prioritization, and resolution procedures",
        ))
    return violations


def _eval_itil_change(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """ITIL Change Enablement practice."""
    violations = []
    if not ctx.get("has_change_management"):
        violations.append(_violation(
            "ITIL-CHG-1", "WARNING",
            "No change management process (ITIL Change Enablement)",
            "Implement ITIL Change Enablement: establish change authority, "
            "risk assessment, and approval workflow for system changes",
        ))
    return violations


def _eval_itil_service_level(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """ITIL Service Level Management practice."""
    violations = []
    if not ctx.get("has_sla"):
        violations.append(_violation(
            "ITIL-SLM-1", "WARNING",
            "No service level agreements defined (ITIL SLM)",
            "Implement ITIL Service Level Management: define, document, "
            "and agree on service levels with stakeholders",
        ))
    return violations


def _eval_itil_catalog(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """ITIL Service Catalogue Management practice."""
    violations = []
    if not ctx.get("has_service_catalog"):
        violations.append(_violation(
            "ITIL-CAT-1", "INFO",
            "No service catalog maintained (ITIL Service Catalogue)",
            "Implement ITIL Service Catalogue: maintain list of available "
            "services with descriptions, SLAs, and request procedures",
        ))
    return violations


ITIL: Framework = {
    "framework_id": "ITIL",
    "name": "ITIL (Information Technology Infrastructure Library)",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "4",
    "url": "https://www.axelos.com/best-practice-solutions/itil",
    "policies": [
        {
            "policy_id": "ITIL-INCIDENT",
            "regulation": "ITIL 4 — Incident Management",
            "severity": "CRITICAL",
            "description": "Incident management process must be established",
            "evaluate": _eval_itil_incident,
            "remediation": "Define incident detection, logging, and resolution process",
        },
        {
            "policy_id": "ITIL-CHANGE",
            "regulation": "ITIL 4 — Change Enablement",
            "severity": "WARNING",
            "description": "Change management with risk assessment must exist",
            "evaluate": _eval_itil_change,
            "remediation": "Establish change authority and approval workflow",
        },
        {
            "policy_id": "ITIL-SLM",
            "regulation": "ITIL 4 — Service Level Management",
            "severity": "WARNING",
            "description": "Service level agreements must be defined and monitored",
            "evaluate": _eval_itil_service_level,
            "remediation": "Define and document SLAs with stakeholders",
        },
        {
            "policy_id": "ITIL-CATALOG",
            "regulation": "ITIL 4 — Service Catalogue Management",
            "severity": "INFO",
            "description": "Service catalog should be maintained",
            "evaluate": _eval_itil_catalog,
            "remediation": "Maintain catalog of available services and SLAs",
        },
    ],
}


# ---- 21. FAIR Risk ----

def _eval_fair_quantification(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """FAIR: Risk must be quantified in financial terms."""
    violations = []
    if not ctx.get("risk_quantified"):
        violations.append(_violation(
            "FAIR-QUANT-1", "WARNING",
            "Risk not quantified in financial terms (FAIR methodology)",
            "Implement FAIR quantification: decompose risk into Loss Event "
            "Frequency (LEF) and Loss Magnitude (LM) with financial estimates",
        ))
    return violations


def _eval_fair_threat_analysis(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """FAIR: Threat event frequency analysis."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "FAIR-TEF-1", "CRITICAL",
            "No threat analysis per FAIR methodology",
            "Conduct FAIR threat analysis: estimate Threat Event Frequency "
            "based on contact frequency and probability of action",
        ))
    return violations


def _eval_fair_vulnerability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """FAIR: Vulnerability analysis."""
    violations = []
    if not ctx.get("has_vulnerability_scanning"):
        violations.append(_violation(
            "FAIR-VULN-1", "WARNING",
            "No vulnerability assessment per FAIR methodology",
            "Conduct FAIR vulnerability analysis: assess strength of controls "
            "relative to threat capability to determine vulnerability level",
        ))
    return violations


FAIR_RISK: Framework = {
    "framework_id": "FAIR_RISK",
    "name": "FAIR (Factor Analysis of Information Risk)",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "3.0",
    "url": "https://www.fairinstitute.org",
    "policies": [
        {
            "policy_id": "FAIR-QUANT",
            "regulation": "FAIR — Risk Quantification",
            "severity": "WARNING",
            "description": "Risk must be quantified in financial terms using FAIR taxonomy",
            "evaluate": _eval_fair_quantification,
            "remediation": "Decompose risk into LEF and LM with financial estimates",
        },
        {
            "policy_id": "FAIR-THREAT",
            "regulation": "FAIR — Threat Event Frequency Analysis",
            "severity": "CRITICAL",
            "description": "Threat event frequency must be estimated",
            "evaluate": _eval_fair_threat_analysis,
            "remediation": "Estimate TEF from contact frequency and probability of action",
        },
        {
            "policy_id": "FAIR-VULN",
            "regulation": "FAIR — Vulnerability Analysis",
            "severity": "WARNING",
            "description": "Control strength must be assessed relative to threat capability",
            "evaluate": _eval_fair_vulnerability,
            "remediation": "Assess vulnerability through control vs. threat analysis",
        },
    ],
}


# ---- 22. CSA AI (Cloud Security Alliance) ----

def _eval_csa_ai_governance(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CSA AI governance controls."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "CSA-AI-GOV-1", "CRITICAL",
            "No AI risk assessment per CSA AI guidance",
            "Implement CSA AI governance: conduct risk assessment covering "
            "data security, model security, and infrastructure security",
        ))
    if not ctx.get("has_cloud_security_policy"):
        violations.append(_violation(
            "CSA-AI-GOV-2", "WARNING",
            "No cloud security policy for AI workloads",
            "Establish cloud security policy per CSA: define shared responsibility, "
            "data location requirements, and encryption standards",
        ))
    return violations


def _eval_csa_ai_data_security(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CSA AI data security controls."""
    violations = []
    if not ctx.get("has_encryption"):
        violations.append(_violation(
            "CSA-AI-DATA-1", "CRITICAL",
            "No encryption for AI data in cloud (CSA AI guidance)",
            "Implement CSA data security: encrypt AI training data, model weights, "
            "and inference data at rest and in transit",
        ))
    if not ctx.get("has_data_governance"):
        violations.append(_violation(
            "CSA-AI-DATA-2", "CRITICAL",
            "No data governance for cloud AI workloads",
            "Per CSA AI guidance: establish data classification, retention, "
            "and disposal policies for cloud-hosted AI data",
        ))
    return violations


def _eval_csa_ai_model_security(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """CSA AI model security controls."""
    violations = []
    if not ctx.get("has_model_access_controls"):
        violations.append(_violation(
            "CSA-AI-MODEL-1", "CRITICAL",
            "No model access controls per CSA AI guidance",
            "Implement CSA model security: restrict access to model artifacts, "
            "implement versioning, and secure the ML pipeline",
        ))
    return violations


CSA_AI: Framework = {
    "framework_id": "CSA_AI",
    "name": "Cloud Security Alliance AI Guidance",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "2024",
    "url": "https://cloudsecurityalliance.org/research/topics/artificial-intelligence",
    "policies": [
        {
            "policy_id": "CSA-AI-GOVERNANCE",
            "regulation": "CSA AI — Governance Controls",
            "severity": "CRITICAL",
            "description": "AI governance must cover risk, cloud security policy, and shared responsibility",
            "evaluate": _eval_csa_ai_governance,
            "remediation": "Establish AI-specific cloud governance and risk assessment",
        },
        {
            "policy_id": "CSA-AI-DATA",
            "regulation": "CSA AI — Data Security Controls",
            "severity": "CRITICAL",
            "description": "AI data must be encrypted and governed in cloud environments",
            "evaluate": _eval_csa_ai_data_security,
            "remediation": "Encrypt AI data and establish cloud data governance",
        },
        {
            "policy_id": "CSA-AI-MODEL",
            "regulation": "CSA AI — Model Security Controls",
            "severity": "CRITICAL",
            "description": "Model artifacts and ML pipeline must be secured",
            "evaluate": _eval_csa_ai_model_security,
            "remediation": "Restrict model access, implement versioning and pipeline security",
        },
    ],
}


# ---- 23. IEEE Ethics ----

def _eval_ieee_human_rights(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """IEEE P7000: Well-being and human rights impact."""
    violations = []
    if not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "IEEE-P7000-1", "CRITICAL",
            "No human rights impact assessment (IEEE P7000)",
            "Conduct IEEE P7000 assessment: evaluate AI system impact on human "
            "rights, well-being, and autonomy of affected stakeholders",
        ))
    return violations


def _eval_ieee_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """IEEE P7001: Transparency of autonomous systems."""
    violations = []
    if not ctx.get("is_explainable"):
        violations.append(_violation(
            "IEEE-P7001-1", "CRITICAL",
            "AI system not transparent per IEEE P7001",
            "Implement IEEE P7001: provide transparency appropriate to "
            "stakeholder type (user, developer, regulator, affected party)",
        ))
    if ctx.get("makes_autonomous_decisions") and not ctx.get("has_audit_trail"):
        violations.append(_violation(
            "IEEE-P7001-2", "CRITICAL",
            "Autonomous decisions lack audit trail (IEEE P7001)",
            "Per IEEE P7001: maintain audit trail of autonomous decisions "
            "with sufficient detail for post-hoc review and accountability",
        ))
    return violations


def _eval_ieee_bias(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """IEEE P7003: Algorithmic bias considerations."""
    violations = []
    if not ctx.get("has_bias_testing"):
        violations.append(_violation(
            "IEEE-P7003-1", "CRITICAL",
            "No algorithmic bias assessment (IEEE P7003)",
            "Implement IEEE P7003: assess algorithm for bias across protected "
            "attributes, document findings, and implement mitigations",
        ))
    if not ctx.get("has_fairness_assessment"):
        violations.append(_violation(
            "IEEE-P7003-2", "WARNING",
            "No fairness assessment conducted (IEEE P7003)",
            "Per IEEE P7003: define fairness criteria, measure disparate impact, "
            "and validate equitable outcomes across demographic groups",
        ))
    return violations


IEEE_ETHICS: Framework = {
    "framework_id": "IEEE_ETHICS",
    "name": "IEEE Ethically Aligned Design",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "2019 (P7000 series)",
    "url": "https://ethicsinaction.ieee.org",
    "policies": [
        {
            "policy_id": "IEEE-RIGHTS",
            "regulation": "IEEE P7000 (Well-Being & Human Rights)",
            "severity": "CRITICAL",
            "description": "AI impact on human rights and well-being must be assessed",
            "evaluate": _eval_ieee_human_rights,
            "remediation": "Conduct human rights impact assessment",
        },
        {
            "policy_id": "IEEE-TRANSPARENCY",
            "regulation": "IEEE P7001 (Transparency of Autonomous Systems)",
            "severity": "CRITICAL",
            "description": "Autonomous systems must be transparent with audit trails",
            "evaluate": _eval_ieee_transparency,
            "remediation": "Implement stakeholder-appropriate transparency and audit trails",
        },
        {
            "policy_id": "IEEE-BIAS",
            "regulation": "IEEE P7003 (Algorithmic Bias Considerations)",
            "severity": "CRITICAL",
            "description": "Algorithmic bias must be assessed and mitigated",
            "evaluate": _eval_ieee_bias,
            "remediation": "Assess bias across protected attributes and document findings",
        },
    ],
}


# ---- 24. OECD AI Principles ----

def _eval_oecd_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Principle 1.3: Transparency and explainability."""
    violations = []
    if not ctx.get("is_explainable"):
        violations.append(_violation(
            "OECD-1.3-1", "CRITICAL",
            "AI system lacks transparency per OECD AI Principle 1.3",
            "Implement OECD Principle 1.3: enable meaningful understanding of "
            "AI system outcomes; disclose when AI is used in decisions",
        ))
    if not ctx.get("has_transparency_report"):
        violations.append(_violation(
            "OECD-1.3-2", "WARNING",
            "No transparency documentation per OECD AI Principles",
            "Per OECD 1.3: provide general information about AI systems to "
            "foster understanding and enable stakeholder scrutiny",
        ))
    return violations


def _eval_oecd_accountability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Principle 1.5: Accountability."""
    violations = []
    if not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "OECD-1.5-1", "CRITICAL",
            "No accountability mechanism per OECD AI Principle 1.5",
            "Implement OECD Principle 1.5: ensure AI actors are accountable "
            "for proper functioning based on their roles and context",
        ))
    if not ctx.get("has_audit_trail"):
        violations.append(_violation(
            "OECD-1.5-2", "WARNING",
            "No audit trail for accountability per OECD AI Principles",
            "Per OECD 1.5: maintain records supporting accountability including "
            "decision logs, testing results, and governance processes",
        ))
    return violations


def _eval_oecd_robustness(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Principle 1.4: Robustness, security, and safety."""
    violations = []
    if not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "OECD-1.4-1", "CRITICAL",
            "No safety and robustness testing per OECD AI Principle 1.4",
            "Implement OECD Principle 1.4: ensure AI systems are robust, "
            "secure, and safe throughout their lifecycle",
        ))
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "OECD-1.4-2", "WARNING",
            "No traceability mechanism per OECD AI Principle 1.4",
            "Per OECD 1.4: enable traceability of AI system outcomes and "
            "establish mechanisms for issue identification and response",
        ))
    return violations


OECD_AI: Framework = {
    "framework_id": "OECD_AI",
    "name": "OECD AI Principles",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "2019 (updated 2024)",
    "url": "https://oecd.ai/en/ai-principles",
    "policies": [
        {
            "policy_id": "OECD-TRANSPARENCY",
            "regulation": "OECD AI — Principle 1.3 (Transparency & Explainability)",
            "severity": "CRITICAL",
            "description": "AI systems must be transparent and explainable",
            "evaluate": _eval_oecd_transparency,
            "remediation": "Implement explainability and publish transparency reports",
        },
        {
            "policy_id": "OECD-ACCOUNTABILITY",
            "regulation": "OECD AI — Principle 1.5 (Accountability)",
            "severity": "CRITICAL",
            "description": "AI actors must be accountable with audit trails",
            "evaluate": _eval_oecd_accountability,
            "remediation": "Establish accountability roles and maintain audit records",
        },
        {
            "policy_id": "OECD-ROBUSTNESS",
            "regulation": "OECD AI — Principle 1.4 (Robustness & Safety)",
            "severity": "CRITICAL",
            "description": "AI systems must be robust, secure, and safe",
            "evaluate": _eval_oecd_robustness,
            "remediation": "Conduct safety testing and establish traceability",
        },
    ],
}


# ---- 25. UNESCO AI Ethics ----

def _eval_unesco_proportionality(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Value: Proportionality and do no harm."""
    violations = []
    if ctx.get("used_in_critical_infrastructure") and not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "UNESCO-PROP-1", "BLOCKING",
            "Critical AI system lacks proportionality assessment (UNESCO)",
            "Implement UNESCO proportionality: ensure AI methods are appropriate "
            "and proportional to legitimate aims; conduct impact assessment",
        ))
    if ctx.get("makes_autonomous_decisions") and not ctx.get("has_human_oversight"):
        violations.append(_violation(
            "UNESCO-PROP-2", "CRITICAL",
            "Autonomous decisions without proportionality safeguards",
            "Per UNESCO: AI should not be used to override human decision-making "
            "in ways disproportionate to the context and potential harm",
        ))
    return violations


def _eval_unesco_safety(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Value: Safety and security."""
    violations = []
    if not ctx.get("has_safety_testing"):
        violations.append(_violation(
            "UNESCO-SAFETY-1", "CRITICAL",
            "No safety measures per UNESCO AI Ethics",
            "Implement UNESCO safety: prevent, avoid, and mitigate risks and "
            "negative impacts throughout the AI system lifecycle",
        ))
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "UNESCO-SAFETY-2", "WARNING",
            "No incident preparedness per UNESCO AI Ethics",
            "Per UNESCO: establish mechanisms to respond to AI system failures "
            "and unintended consequences",
        ))
    return violations


def _eval_unesco_fairness(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Value: Fairness and non-discrimination."""
    violations = []
    if not ctx.get("has_bias_testing"):
        violations.append(_violation(
            "UNESCO-FAIR-1", "CRITICAL",
            "No fairness assessment per UNESCO AI Ethics",
            "Implement UNESCO fairness: promote social justice, prevent bias, "
            "and ensure AI benefits are inclusive and equitably distributed",
        ))
    if not ctx.get("has_fairness_assessment"):
        violations.append(_violation(
            "UNESCO-FAIR-2", "WARNING",
            "No non-discrimination assessment per UNESCO AI Ethics",
            "Per UNESCO: assess AI system for discriminatory outcomes and ensure "
            "equitable access and treatment",
        ))
    return violations


def _eval_unesco_sustainability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Value: Sustainability."""
    violations = []
    if not ctx.get("has_sustainability_assessment"):
        violations.append(_violation(
            "UNESCO-SUST-1", "WARNING",
            "No sustainability assessment per UNESCO AI Ethics",
            "Implement UNESCO sustainability: assess environmental impact of AI "
            "system including energy consumption and carbon footprint",
        ))
    return violations


UNESCO_AI: Framework = {
    "framework_id": "UNESCO_AI",
    "name": "UNESCO Recommendation on the Ethics of Artificial Intelligence",
    "jurisdiction": "INTERNATIONAL",
    "category": "it_governance_risk",
    "version": "2021",
    "url": "https://www.unesco.org/en/artificial-intelligence/recommendation-ethics",
    "policies": [
        {
            "policy_id": "UNESCO-PROPORTIONALITY",
            "regulation": "UNESCO AI Ethics — Proportionality & Do No Harm",
            "severity": "BLOCKING",
            "description": "AI use must be proportional to legitimate aims",
            "evaluate": _eval_unesco_proportionality,
            "remediation": "Conduct proportionality assessment for critical AI systems",
        },
        {
            "policy_id": "UNESCO-SAFETY",
            "regulation": "UNESCO AI Ethics — Safety & Security",
            "severity": "CRITICAL",
            "description": "AI systems must have safety measures and incident preparedness",
            "evaluate": _eval_unesco_safety,
            "remediation": "Implement safety testing and incident response",
        },
        {
            "policy_id": "UNESCO-FAIRNESS",
            "regulation": "UNESCO AI Ethics — Fairness & Non-Discrimination",
            "severity": "CRITICAL",
            "description": "AI must promote fairness and prevent discrimination",
            "evaluate": _eval_unesco_fairness,
            "remediation": "Conduct bias testing and fairness assessment",
        },
        {
            "policy_id": "UNESCO-SUSTAINABILITY",
            "regulation": "UNESCO AI Ethics — Sustainability",
            "severity": "WARNING",
            "description": "Environmental impact of AI must be assessed",
            "evaluate": _eval_unesco_sustainability,
            "remediation": "Assess energy consumption and carbon footprint",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# NIS2 — EU Network and Information Security Directive 2
# ═══════════════════════════════════════════════════════════════════════════


def _eval_nis2_risk_management(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """NIS2 Art. 21 — Risk management measures."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "NIS2-RISK-1", "BLOCKING",
            "No risk management measures per NIS2 Art. 21",
            "Implement risk management: conduct regular risk assessments and "
            "apply appropriate security measures proportionate to the risk",
        ))
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "NIS2-RISK-2", "CRITICAL",
            "No incident handling procedures per NIS2 Art. 21(2)",
            "Establish incident handling procedures including detection, "
            "analysis, containment, and recovery processes",
        ))
    return violations


def _eval_nis2_reporting(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """NIS2 Art. 23 — Incident reporting obligations."""
    violations = []
    if not ctx.get("has_audit_trail"):
        violations.append(_violation(
            "NIS2-REPORT-1", "CRITICAL",
            "No incident reporting capability per NIS2 Art. 23",
            "Implement audit trail and incident reporting: notify CSIRT within "
            "24 hours of significant incidents, full report within 72 hours",
        ))
    return violations


def _eval_nis2_supply_chain(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """NIS2 Art. 21(2)(d) — Supply chain security."""
    violations = []
    if not ctx.get("has_data_provenance"):
        violations.append(_violation(
            "NIS2-SUPPLY-1", "WARNING",
            "No supply chain security measures per NIS2 Art. 21(2)(d)",
            "Assess and manage supply chain risks: verify security practices "
            "of direct suppliers and service providers",
        ))
    return violations


NIS2: Framework = {
    "framework_id": "NIS2",
    "name": "EU Network and Information Security Directive 2 (NIS2)",
    "jurisdiction": "EU",
    "category": "security_infrastructure",
    "version": "2022/2555",
    "url": "https://eur-lex.europa.eu/eli/dir/2022/2555",
    "policies": [
        {
            "policy_id": "NIS2-RISK-MGMT",
            "regulation": "NIS2 Art. 21 — Cybersecurity Risk Management",
            "severity": "BLOCKING",
            "description": "Essential and important entities must implement risk management measures",
            "evaluate": _eval_nis2_risk_management,
            "remediation": "Implement comprehensive cybersecurity risk management framework",
        },
        {
            "policy_id": "NIS2-INCIDENT-REPORTING",
            "regulation": "NIS2 Art. 23 — Incident Reporting",
            "severity": "CRITICAL",
            "description": "Significant incidents must be reported to CSIRT within 24 hours",
            "evaluate": _eval_nis2_reporting,
            "remediation": "Establish incident detection, reporting, and notification procedures",
        },
        {
            "policy_id": "NIS2-SUPPLY-CHAIN",
            "regulation": "NIS2 Art. 21(2)(d) — Supply Chain Security",
            "severity": "WARNING",
            "description": "Supply chain and third-party security must be assessed",
            "evaluate": _eval_nis2_supply_chain,
            "remediation": "Assess and manage supply chain cybersecurity risks",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# DORA — EU Digital Operational Resilience Act
# ═══════════════════════════════════════════════════════════════════════════


def _eval_dora_ict_risk(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DORA Art. 6 — ICT risk management framework."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "DORA-ICT-1", "BLOCKING",
            "No ICT risk management framework per DORA Art. 6",
            "Establish ICT risk management framework: identify, protect, "
            "detect, respond to, and recover from ICT-related incidents",
        ))
    if not ctx.get("has_backup_recovery"):
        violations.append(_violation(
            "DORA-ICT-2", "CRITICAL",
            "No business continuity / backup per DORA Art. 11",
            "Implement ICT business continuity plans with backup and recovery "
            "procedures, tested at least annually",
        ))
    return violations


def _eval_dora_incident_management(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DORA Art. 17 — ICT-related incident management."""
    violations = []
    if not ctx.get("has_incident_response"):
        violations.append(_violation(
            "DORA-INC-1", "CRITICAL",
            "No ICT incident management process per DORA Art. 17",
            "Implement incident management: classify, report, and resolve "
            "ICT-related incidents with root cause analysis",
        ))
    if not ctx.get("has_audit_trail"):
        violations.append(_violation(
            "DORA-INC-2", "CRITICAL",
            "No incident logging per DORA Art. 17(3)",
            "Maintain audit trail of all ICT incidents including timeline, "
            "impact assessment, and remediation actions",
        ))
    return violations


def _eval_dora_third_party(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DORA Art. 28 — Third-party ICT risk."""
    violations = []
    if not ctx.get("has_data_provenance"):
        violations.append(_violation(
            "DORA-TPP-1", "WARNING",
            "No third-party ICT provider risk assessment per DORA Art. 28",
            "Assess third-party ICT providers: maintain register of "
            "outsourcing arrangements and assess concentration risk",
        ))
    return violations


DORA: Framework = {
    "framework_id": "DORA",
    "name": "EU Digital Operational Resilience Act (DORA)",
    "jurisdiction": "EU",
    "category": "security_infrastructure",
    "version": "2022/2554",
    "url": "https://eur-lex.europa.eu/eli/reg/2022/2554",
    "policies": [
        {
            "policy_id": "DORA-ICT-RISK",
            "regulation": "DORA Art. 6 — ICT Risk Management",
            "severity": "BLOCKING",
            "description": "Financial entities must have ICT risk management frameworks",
            "evaluate": _eval_dora_ict_risk,
            "remediation": "Establish comprehensive ICT risk management framework",
        },
        {
            "policy_id": "DORA-INCIDENT-MGMT",
            "regulation": "DORA Art. 17 — Incident Management",
            "severity": "CRITICAL",
            "description": "ICT incidents must be classified, managed, and reported",
            "evaluate": _eval_dora_incident_management,
            "remediation": "Implement ICT incident management and reporting process",
        },
        {
            "policy_id": "DORA-THIRD-PARTY",
            "regulation": "DORA Art. 28 — Third-Party ICT Risk",
            "severity": "WARNING",
            "description": "Third-party ICT provider risks must be assessed and managed",
            "evaluate": _eval_dora_third_party,
            "remediation": "Maintain register and assessment of third-party ICT providers",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# DSA — EU Digital Services Act
# ═══════════════════════════════════════════════════════════════════════════


def _eval_dsa_transparency(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DSA Art. 27 — Transparency of recommender systems."""
    violations = []
    if not ctx.get("algorithmic_transparency"):
        violations.append(_violation(
            "DSA-TRANS-1", "BLOCKING",
            "No algorithmic transparency per DSA Art. 27",
            "Implement algorithmic transparency: disclose main parameters of "
            "recommender systems and provide non-profiling alternatives",
        ))
    return violations


def _eval_dsa_risk_assessment(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DSA Art. 34 — Risk assessment for very large platforms."""
    violations = []
    if not ctx.get("has_risk_assessment"):
        violations.append(_violation(
            "DSA-RISK-1", "CRITICAL",
            "No systemic risk assessment per DSA Art. 34",
            "Conduct risk assessment: identify systemic risks including "
            "illegal content dissemination and fundamental rights impacts",
        ))
    if not ctx.get("has_impact_assessment"):
        violations.append(_violation(
            "DSA-RISK-2", "CRITICAL",
            "No impact assessment per DSA Art. 34(1)(d)",
            "Assess negative effects on civic discourse, elections, "
            "public security, and mental health",
        ))
    return violations


def _eval_dsa_audit(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DSA Art. 37 — Independent auditing."""
    violations = []
    if not ctx.get("has_audit_trail"):
        violations.append(_violation(
            "DSA-AUDIT-1", "WARNING",
            "No independent audit mechanism per DSA Art. 37",
            "Submit to independent annual audit of compliance with "
            "transparency and risk management obligations",
        ))
    return violations


DSA: Framework = {
    "framework_id": "DSA",
    "name": "EU Digital Services Act (DSA)",
    "jurisdiction": "EU",
    "category": "regional_regulations",
    "version": "2022/2065",
    "url": "https://eur-lex.europa.eu/eli/reg/2022/2065",
    "policies": [
        {
            "policy_id": "DSA-TRANSPARENCY",
            "regulation": "DSA Art. 27 — Algorithmic Transparency",
            "severity": "BLOCKING",
            "description": "Recommender systems must be transparent with non-profiling options",
            "evaluate": _eval_dsa_transparency,
            "remediation": "Disclose recommender system parameters and offer alternatives",
        },
        {
            "policy_id": "DSA-SYSTEMIC-RISK",
            "regulation": "DSA Art. 34 — Systemic Risk Assessment",
            "severity": "CRITICAL",
            "description": "Very large platforms must assess systemic risks",
            "evaluate": _eval_dsa_risk_assessment,
            "remediation": "Conduct annual systemic risk and impact assessments",
        },
        {
            "policy_id": "DSA-AUDIT",
            "regulation": "DSA Art. 37 — Independent Audit",
            "severity": "WARNING",
            "description": "Platforms must undergo independent compliance audits",
            "evaluate": _eval_dsa_audit,
            "remediation": "Engage independent auditors for annual compliance review",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# DMA — EU Digital Markets Act
# ═══════════════════════════════════════════════════════════════════════════


def _eval_dma_interoperability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DMA Art. 7 — Interoperability obligations."""
    violations = []
    if not ctx.get("algorithmic_transparency"):
        violations.append(_violation(
            "DMA-INTEROP-1", "CRITICAL",
            "No interoperability / transparency per DMA Art. 6-7",
            "Ensure interoperability: provide transparent access to ranking, "
            "indexing, and classification parameters used by AI systems",
        ))
    return violations


def _eval_dma_data_portability(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DMA Art. 6(9) — Data portability."""
    violations = []
    if not ctx.get("has_access_controls"):
        violations.append(_violation(
            "DMA-PORT-1", "CRITICAL",
            "No data portability mechanism per DMA Art. 6(9)",
            "Enable effective data portability: provide tools for end users "
            "and business users to port their data in real time",
        ))
    return violations


def _eval_dma_profiling(ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """DMA Art. 5(2) — Profiling consent."""
    violations = []
    if not ctx.get("has_consent_mechanism"):
        violations.append(_violation(
            "DMA-PROFILE-1", "BLOCKING",
            "No profiling consent per DMA Art. 5(2)",
            "Obtain explicit consent for profiling: do not combine personal "
            "data from core platform services without user consent",
        ))
    return violations


DMA: Framework = {
    "framework_id": "DMA",
    "name": "EU Digital Markets Act (DMA)",
    "jurisdiction": "EU",
    "category": "regional_regulations",
    "version": "2022/1925",
    "url": "https://eur-lex.europa.eu/eli/reg/2022/1925",
    "policies": [
        {
            "policy_id": "DMA-INTEROPERABILITY",
            "regulation": "DMA Art. 6-7 — Interoperability & Transparency",
            "severity": "CRITICAL",
            "description": "Gatekeepers must ensure interoperability and algorithmic transparency",
            "evaluate": _eval_dma_interoperability,
            "remediation": "Provide transparent access to AI system parameters",
        },
        {
            "policy_id": "DMA-DATA-PORTABILITY",
            "regulation": "DMA Art. 6(9) — Data Portability",
            "severity": "CRITICAL",
            "description": "End users must be able to port their data effectively",
            "evaluate": _eval_dma_data_portability,
            "remediation": "Implement real-time data portability tools for users",
        },
        {
            "policy_id": "DMA-PROFILING-CONSENT",
            "regulation": "DMA Art. 5(2) — Profiling Consent",
            "severity": "BLOCKING",
            "description": "Explicit consent required for cross-service profiling",
            "evaluate": _eval_dma_profiling,
            "remediation": "Obtain explicit consent before combining personal data across services",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# ALL FRAMEWORKS — Exported list
# ═══════════════════════════════════════════════════════════════════════════

ALL_FRAMEWORKS: List[Framework] = [
    # Category 1 — AI-Specific Risk & Safety
    NIST_AI_RMF,
    EU_AI_ACT,
    ISO_42001,
    MITRE_ATLAS,
    OWASP_AI_TOP_10,
    # Category 2 — Regional Regulations
    SINGAPORE_AI_GOV,
    UK_AI_ACT,
    CANADA_AIDA,
    CHINA_AI_REGS,
    US_EO_14110,
    DSA,
    DMA,
    # Category 3 — Data Privacy
    GDPR,
    CCPA,
    HIPAA,
    # Category 4 — Security & Infrastructure
    ISO_27001,
    NIST_CSF,
    ZERO_TRUST,
    CIS_CONTROLS,
    SOC_2,
    NIS2,
    DORA,
    # Category 5 — IT Governance & Risk
    COBIT,
    ITIL,
    FAIR_RISK,
    CSA_AI,
    IEEE_ETHICS,
    OECD_AI,
    UNESCO_AI,
]

# Category labels
CATEGORIES = {
    "ai_risk_safety": "AI-Specific Risk & Safety",
    "regional_regulations": "Regional Regulations",
    "data_privacy": "Data Privacy",
    "security_infrastructure": "Security & Infrastructure",
    "it_governance_risk": "IT Governance & Risk",
}
