"""Regulatory Report Generator — EU AI Act, NIST AI RMF, ISO 42001, HITRUST, NYC LL144, Colorado SB169, SOC2, GDPR."""

from datetime import datetime
from typing import Any, Dict, Optional


def generate_eu_ai_act_report(
    system_name: str,
    risk_tier: str = "high",
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate EU AI Act compliance report."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    requirements = {
        "article_9_risk_management": {
            "status": "compliant" if ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "Risk management system established and maintained",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
        "article_10_data_governance": {
            "status": "compliant" if not ctx.get("pii_detected", True) else "needs_review",
            "description": "Training and validation data governance",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'findings detected'}",
        },
        "article_11_technical_documentation": {
            "status": "compliant" if ctx.get("has_model_card", False) else "non_compliant",
            "description": "Technical documentation maintained",
            "evidence": f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "article_13_transparency": {
            "status": "compliant" if ctx.get("has_explanation", False) else "non_compliant",
            "description": "Transparency and information provision to users",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'not configured'}",
        },
        "article_14_human_oversight": {
            "status": "compliant" if ctx.get("human_oversight", False) else "needs_review",
            "description": "Human oversight measures in place",
            "evidence": f"Human-in-the-loop: {'enabled' if ctx.get('human_oversight', False) else 'not confirmed'}",
        },
        "article_15_accuracy_robustness": {
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 else "non_compliant",
            "description": "Accuracy, robustness and cybersecurity",
            "evidence": f"Drift score: {ctx.get('drift_score', 'N/A')}",
        },
    }

    compliant = sum(1 for r in requirements.values() if r["status"] == "compliant")
    total = len(requirements)

    return {
        "report_type": "EU AI Act Compliance",
        "system_name": system_name,
        "risk_tier": risk_tier,
        "generated_at": now,
        "compliance_score": round(compliant / total * 100, 1),
        "requirements": requirements,
        "summary": {
            "compliant": compliant,
            "non_compliant": sum(1 for r in requirements.values() if r["status"] == "non_compliant"),
            "needs_review": sum(1 for r in requirements.values() if r["status"] == "needs_review"),
            "total": total,
        },
        "recommendation": "System meets EU AI Act requirements" if compliant == total else "Action required to achieve full compliance",
    }


def generate_nist_ai_rmf_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate NIST AI Risk Management Framework report."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    functions = {
        "govern": {
            "score": 0.8 if ctx.get("has_policy", False) else 0.3,
            "status": "implemented" if ctx.get("has_policy", False) else "partial",
            "practices": [
                "AI risk management policy established" if ctx.get("has_policy") else "Policy needed",
                "Roles and responsibilities defined",
            ],
        },
        "map": {
            "score": 0.7 if ctx.get("has_model_card", False) else 0.2,
            "status": "implemented" if ctx.get("has_model_card", False) else "partial",
            "practices": [
                "AI system cataloged in registry",
                f"Risk tier classified: {ctx.get('risk_tier', 'unclassified')}",
            ],
        },
        "measure": {
            "score": 0.9 if ctx.get("risk_score") is not None else 0.1,
            "status": "implemented" if ctx.get("risk_score") is not None else "not_started",
            "practices": [
                f"Risk scoring active: {ctx.get('risk_score', 'N/A')}",
                f"Drift monitoring: {'active' if ctx.get('drift_score') is not None else 'inactive'}",
                f"Fairness testing: {'active' if ctx.get('fairness_tested', False) else 'inactive'}",
            ],
        },
        "manage": {
            "score": 0.6 if ctx.get("has_incident_process", False) else 0.2,
            "status": "partial",
            "practices": [
                "Incident management process defined",
                "Continuous monitoring deployed",
            ],
        },
    }

    avg_score = sum(f["score"] for f in functions.values()) / len(functions)

    return {
        "report_type": "NIST AI RMF Assessment",
        "system_name": system_name,
        "framework_version": "1.0",
        "generated_at": now,
        "overall_maturity": round(avg_score * 100, 1),
        "functions": functions,
        "recommendation": "Strong AI risk management posture" if avg_score > 0.7 else "Improvements needed in AI risk management",
    }


def generate_iso_42001_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate ISO 42001 AI Management System report."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    clauses = {
        "clause_4_context": {
            "status": "conforming",
            "description": "Understanding the organization and its context",
        },
        "clause_5_leadership": {
            "status": "conforming" if ctx.get("has_policy", False) else "opportunity_for_improvement",
            "description": "Leadership and commitment to AI management",
        },
        "clause_6_planning": {
            "status": "conforming" if ctx.get("risk_score") is not None else "non_conforming",
            "description": "Planning for AI risk and opportunities",
        },
        "clause_7_support": {
            "status": "conforming",
            "description": "Resources, competence, and awareness",
        },
        "clause_8_operation": {
            "status": "conforming" if ctx.get("has_model_card", False) else "opportunity_for_improvement",
            "description": "Operational planning and control",
        },
        "clause_9_performance": {
            "status": "conforming" if ctx.get("drift_score") is not None else "non_conforming",
            "description": "Performance evaluation and monitoring",
        },
        "clause_10_improvement": {
            "status": "conforming" if ctx.get("has_incident_process", False) else "opportunity_for_improvement",
            "description": "Continual improvement",
        },
    }

    conforming = sum(1 for c in clauses.values() if c["status"] == "conforming")

    return {
        "report_type": "ISO 42001 AIMS Assessment",
        "system_name": system_name,
        "generated_at": now,
        "conformity_score": round(conforming / len(clauses) * 100, 1),
        "clauses": clauses,
        "summary": {
            "conforming": conforming,
            "opportunity_for_improvement": sum(1 for c in clauses.values() if c["status"] == "opportunity_for_improvement"),
            "non_conforming": sum(1 for c in clauses.values() if c["status"] == "non_conforming"),
            "total": len(clauses),
        },
        "certification_ready": conforming == len(clauses),
    }


def generate_hitrust_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate HITRUST AI Assurance report for healthcare AI systems."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    domains = {
        "data_protection": {
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "Protected health information (PHI) and data protection controls",
            "evidence": f"PII/PHI scan: {'clean' if not ctx.get('pii_detected', True) else 'findings detected'}",
        },
        "access_control": {
            "status": "compliant" if ctx.get("has_rbac", False) else "needs_review",
            "description": "Role-based access controls for AI systems",
        },
        "audit_logging": {
            "status": "compliant" if ctx.get("has_audit_trail", False) else "non_compliant",
            "description": "Comprehensive audit trail for AI decisions",
            "evidence": f"Audit ledger: {'active' if ctx.get('has_audit_trail', False) else 'not configured'}",
        },
        "incident_response": {
            "status": "compliant" if ctx.get("has_incident_process", False) else "non_compliant",
            "description": "AI incident detection, response, and remediation",
        },
        "vendor_management": {
            "status": "compliant" if ctx.get("models_registered", False) else "needs_review",
            "description": "Third-party AI model and vendor risk management",
        },
        "model_validation": {
            "status": "compliant" if ctx.get("fairness_tested", False) else "non_compliant",
            "description": "AI model validation including bias and fairness testing",
        },
    }

    compliant = sum(1 for d in domains.values() if d["status"] == "compliant")
    total = len(domains)

    return {
        "report_type": "HITRUST AI Assurance",
        "system_name": system_name,
        "generated_at": now,
        "compliance_score": round(compliant / total * 100, 1),
        "domains": domains,
        "summary": {
            "compliant": compliant,
            "non_compliant": sum(1 for d in domains.values() if d["status"] == "non_compliant"),
            "needs_review": sum(1 for d in domains.values() if d["status"] == "needs_review"),
            "total": total,
        },
        "recommendation": "System meets HITRUST AI requirements" if compliant == total else "Remediation required for HITRUST AI certification",
    }


def generate_nyc_ll144_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate NYC Local Law 144 compliance report for automated employment decisions."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    requirements = {
        "bias_audit": {
            "status": "compliant" if ctx.get("fairness_tested", False) else "non_compliant",
            "description": "Annual independent bias audit conducted",
            "evidence": f"Fairness testing: {'completed' if ctx.get('fairness_tested', False) else 'not conducted'}",
            "penalty": "Up to $1,500 per violation",
        },
        "public_notice": {
            "status": "compliant" if ctx.get("public_notice_posted", False) else "non_compliant",
            "description": "Bias audit results publicly posted on employer's website",
        },
        "candidate_notification": {
            "status": "compliant" if ctx.get("candidate_notified", False) else "non_compliant",
            "description": "Candidates notified that AEDT is being used within 10 business days",
        },
        "disparate_impact": {
            "status": "compliant" if ctx.get("disparate_impact_ratio", 0) >= 0.8 else "non_compliant",
            "description": "Disparate impact ratio meets 4/5ths rule across protected classes",
            "evidence": f"DI ratio: {ctx.get('disparate_impact_ratio', 'N/A')}",
        },
        "annual_audit": {
            "status": "compliant" if ctx.get("last_audit_within_year", False) else "non_compliant",
            "description": "Bias audit conducted within the last year",
        },
    }

    compliant = sum(1 for r in requirements.values() if r["status"] == "compliant")
    total = len(requirements)

    return {
        "report_type": "NYC Local Law 144 (AEDT)",
        "system_name": system_name,
        "generated_at": now,
        "jurisdiction": "New York City",
        "applies_to": "Automated Employment Decision Tools (AEDT)",
        "compliance_score": round(compliant / total * 100, 1),
        "requirements": requirements,
        "summary": {"compliant": compliant, "non_compliant": total - compliant, "total": total},
        "recommendation": "System meets NYC LL144 requirements" if compliant == total else "Non-compliant with NYC LL144 — risk of fines up to $1,500 per violation",
    }


def generate_colorado_sb169_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate Colorado SB 21-169 compliance report for insurance AI."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    requirements = {
        "impact_assessment": {
            "status": "compliant" if ctx.get("impact_assessment_done", False) else "non_compliant",
            "description": "Algorithmic impact assessment conducted before deployment",
        },
        "bias_testing": {
            "status": "compliant" if ctx.get("fairness_tested", False) else "non_compliant",
            "description": "Testing for unfairly discriminatory outcomes",
            "evidence": f"Fairness testing: {'completed' if ctx.get('fairness_tested', False) else 'not conducted'}",
        },
        "consumer_disclosure": {
            "status": "compliant" if ctx.get("consumer_disclosed", False) else "non_compliant",
            "description": "Consumers informed of algorithmic decision-making use",
        },
        "opt_out_mechanism": {
            "status": "compliant" if ctx.get("opt_out_available", False) else "non_compliant",
            "description": "Consumers can opt out of algorithmic decision-making",
        },
        "governance_framework": {
            "status": "compliant" if ctx.get("has_policy", False) else "non_compliant",
            "description": "AI governance framework established and documented",
        },
    }

    compliant = sum(1 for r in requirements.values() if r["status"] == "compliant")
    total = len(requirements)

    return {
        "report_type": "Colorado SB 21-169",
        "system_name": system_name,
        "generated_at": now,
        "jurisdiction": "Colorado",
        "applies_to": "Insurance industry AI/algorithmic systems",
        "compliance_score": round(compliant / total * 100, 1),
        "requirements": requirements,
        "summary": {"compliant": compliant, "non_compliant": total - compliant, "total": total},
        "recommendation": "System meets Colorado SB 21-169 requirements" if compliant == total else "Action required for Colorado algorithmic compliance",
    }


def generate_soc2_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate SOC 2 Type II readiness report for AI systems."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    criteria = {
        "security": {
            "status": "compliant" if not ctx.get("injection_detected", True) else "non_compliant",
            "description": "System protected against unauthorized access and adversarial inputs",
        },
        "availability": {
            "status": "compliant",
            "description": "System operates and is available as committed",
        },
        "processing_integrity": {
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 else "non_compliant",
            "description": "System processing is complete, valid, accurate, and authorized",
        },
        "confidentiality": {
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "Confidential information is protected as committed",
        },
        "privacy": {
            "status": "compliant" if ctx.get("data_governance_active", False) else "needs_review",
            "description": "Personal information collected, used, retained, and disposed properly",
        },
    }

    compliant = sum(1 for c in criteria.values() if c["status"] == "compliant")
    total = len(criteria)

    return {
        "report_type": "SOC 2 Type II Readiness",
        "system_name": system_name,
        "generated_at": now,
        "compliance_score": round(compliant / total * 100, 1),
        "trust_service_criteria": criteria,
        "summary": {"compliant": compliant, "non_compliant": total - compliant, "total": total},
        "recommendation": "Ready for SOC 2 Type II audit" if compliant == total else "Remediation needed before SOC 2 audit engagement",
    }


def generate_gdpr_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate GDPR compliance report for AI systems processing personal data."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    principles = {
        "lawful_processing": {
            "status": "compliant" if ctx.get("legal_basis_documented", False) else "needs_review",
            "description": "Legal basis for processing established (Art. 6)",
        },
        "data_minimization": {
            "status": "compliant" if ctx.get("data_minimized", False) else "needs_review",
            "description": "Only necessary data collected and processed (Art. 5(1)(c))",
        },
        "purpose_limitation": {
            "status": "compliant" if ctx.get("purpose_documented", False) else "needs_review",
            "description": "Data processed only for specified purposes (Art. 5(1)(b))",
        },
        "accuracy": {
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 else "non_compliant",
            "description": "Data and model outputs are accurate and up to date (Art. 5(1)(d))",
        },
        "right_to_explanation": {
            "status": "compliant" if ctx.get("has_explanation", False) else "non_compliant",
            "description": "Meaningful information about automated decision logic (Art. 22)",
        },
        "dpia_completed": {
            "status": "compliant" if ctx.get("dpia_done", False) else "non_compliant",
            "description": "Data Protection Impact Assessment completed (Art. 35)",
        },
        "data_protection": {
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "Technical measures to protect personal data (Art. 32)",
        },
    }

    compliant = sum(1 for p in principles.values() if p["status"] == "compliant")
    total = len(principles)

    return {
        "report_type": "GDPR AI Compliance",
        "system_name": system_name,
        "generated_at": now,
        "jurisdiction": "European Union",
        "compliance_score": round(compliant / total * 100, 1),
        "principles": principles,
        "summary": {"compliant": compliant, "non_compliant": total - compliant, "needs_review": sum(1 for p in principles.values() if p["status"] == "needs_review"), "total": total},
        "penalties": {"max_fine": "4% of annual global turnover or EUR 20M (whichever is greater)"},
        "recommendation": "System meets GDPR requirements" if compliant == total else "GDPR compliance gaps detected — risk of significant fines",
    }
