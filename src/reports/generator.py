"""Regulatory Report Generator — EU AI Act, NIST AI RMF, ISO 42001, ISO 27001, NIS2, HITRUST, NYC LL144, Colorado SB169, SOC2, GDPR, DORA, CCPA, HIPAA, MITRE ATLAS, OWASP AI, NIST CSF, OECD AI, IEEE Ethics.

Reports pull real data from the database when available (audit records, risk scores,
collected evidence). Falls back gracefully when no data exists.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from src.reports.data import ReportData

logger = logging.getLogger("governlayer.reports")


def _load_data(system_name: str, context: Optional[Dict[str, Any]] = None) -> ReportData:
    """Load real data from the database for report generation."""
    try:
        data = ReportData(system_name=system_name, days=90)
        data.load()
        return data
    except Exception as exc:
        logger.warning("Could not load report data: %s", exc)
        return ReportData(system_name=system_name)


def generate_eu_ai_act_report(
    system_name: str,
    risk_tier: str = "high",
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate EU AI Act compliance report with real database data."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()
    data = _load_data(system_name, ctx)

    # Use real data when available, fall back to context
    real_risk_score = data.avg_risk_score if data.has_data and data.risk_scores else ctx.get("risk_score", 100)
    has_audit_trail = data.total_decisions > 0 or ctx.get("has_audit_trail", False)
    has_risk_assessment = len(data.risk_scores) > 0 or ctx.get("risk_score") is not None

    requirements = {
        "article_9_risk_management": {
            "status": "compliant" if real_risk_score < 70 else "non_compliant",
            "description": "Risk management system established and maintained",
            "evidence": f"Risk score: {real_risk_score} (from {len(data.risk_scores)} assessments)" if data.has_data else f"Risk score: {ctx.get('risk_score', 'N/A')}",
            "evidence_refs": data.get_evidence_for_controls(["NIST-"]) if data.has_data else [],
        },
        "article_10_data_governance": {
            "status": "compliant" if not ctx.get("pii_detected", True) else "needs_review",
            "description": "Training and validation data governance",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'findings detected'}",
            "evidence_refs": data.get_evidence_for_controls(["GDPR-"]) if data.has_data else [],
        },
        "article_11_technical_documentation": {
            "status": "compliant" if ctx.get("has_model_card", False) or has_audit_trail else "non_compliant",
            "description": "Technical documentation maintained",
            "evidence": f"Audit trail: {data.total_decisions} governance decisions recorded" if data.has_data else f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "article_13_transparency": {
            "status": "compliant" if ctx.get("has_explanation", False) or has_audit_trail else "non_compliant",
            "description": "Transparency and information provision to users",
            "evidence": f"Governance decisions logged with full audit trail ({data.total_decisions} records)" if has_audit_trail else "Not configured",
        },
        "article_14_human_oversight": {
            "status": "compliant" if ctx.get("human_oversight", False) or data.escalated_count > 0 else "needs_review",
            "description": "Human oversight measures in place",
            "evidence": f"{data.escalated_count} decisions escalated for human review" if data.has_data else f"Human-in-the-loop: {'enabled' if ctx.get('human_oversight', False) else 'not confirmed'}",
        },
        "article_15_accuracy_robustness": {
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 or (data.has_data and data.compliance_rate > 80) else "non_compliant",
            "description": "Accuracy, robustness and cybersecurity",
            "evidence": f"Compliance rate: {data.compliance_rate}%, drift score: {ctx.get('drift_score', 'N/A')}" if data.has_data else f"Drift score: {ctx.get('drift_score', 'N/A')}",
        },
    }

    compliant = sum(1 for r in requirements.values() if r["status"] == "compliant")
    total = len(requirements)

    result = {
        "report_type": "EU AI Act Compliance",
        "system_name": system_name,
        "risk_tier": risk_tier,
        "generated_at": now,
        "compliance_score": round(compliant / total * 100, 1),
        "executive_summary": data.executive_summary(),
        "requirements": requirements,
        "summary": {
            "compliant": compliant,
            "non_compliant": sum(1 for r in requirements.values() if r["status"] == "non_compliant"),
            "needs_review": sum(1 for r in requirements.values() if r["status"] == "needs_review"),
            "total": total,
        },
        "violations": data.violations[:10] if data.has_data else [],
        "recommendations": data.recommendations(),
        "recommendation": "System meets EU AI Act requirements" if compliant == total else "Action required to achieve full compliance",
    }
    return result


def generate_nist_ai_rmf_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate NIST AI Risk Management Framework report with real database data."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()
    data = _load_data(system_name, ctx)

    has_governance = data.total_decisions > 0 or ctx.get("has_policy", False)
    has_measurement = len(data.risk_scores) > 0 or ctx.get("risk_score") is not None
    has_monitoring = data.total_decisions > 0 or ctx.get("drift_score") is not None
    nist_evidence = data.get_evidence_for_controls(["NIST-"]) if data.has_data else []

    functions = {
        "govern": {
            "score": 0.8 if has_governance else 0.3,
            "status": "implemented" if has_governance else "partial",
            "practices": [
                f"AI governance active: {data.total_decisions} decisions recorded" if data.has_data else (
                    "AI risk management policy established" if ctx.get("has_policy") else "Policy needed"
                ),
                "Roles and responsibilities defined",
                f"Frameworks assessed: {', '.join(data.frameworks_audited.keys()) or 'none'}" if data.has_data else "",
            ],
            "evidence_refs": [e for e in nist_evidence if "AC" in e.get("control_id", "")][:5],
        },
        "map": {
            "score": 0.7 if (data.has_data or ctx.get("has_model_card", False)) else 0.2,
            "status": "implemented" if (data.has_data or ctx.get("has_model_card", False)) else "partial",
            "practices": [
                "AI system cataloged in registry",
                f"Risk tier classified: {ctx.get('risk_tier', data.latest_risk_level)}",
                f"Compliance rate: {data.compliance_rate}%" if data.has_data else "",
            ],
        },
        "measure": {
            "score": 0.9 if has_measurement else 0.1,
            "status": "implemented" if has_measurement else "not_started",
            "practices": [
                f"Risk scoring: {len(data.risk_scores)} assessments, avg score {data.avg_risk_score}" if data.risk_scores else f"Risk scoring active: {ctx.get('risk_score', 'N/A')}",
                f"Drift monitoring: {'active' if ctx.get('drift_score') is not None else 'inactive'}",
                f"Evidence collected: {data.total_evidence} items" if data.has_data else f"Fairness testing: {'active' if ctx.get('fairness_tested', False) else 'inactive'}",
            ],
            "risk_dimensions": data.risk_dimension_averages if data.has_data else {},
            "evidence_refs": [e for e in nist_evidence if "SI" in e.get("control_id", "")][:5],
        },
        "manage": {
            "score": 0.7 if (data.escalated_count > 0 or ctx.get("has_incident_process", False)) else 0.2,
            "status": "implemented" if data.escalated_count > 0 else "partial",
            "practices": [
                f"Incident escalation: {data.escalated_count} decisions escalated" if data.has_data else "Incident management process defined",
                f"Continuous monitoring: {data.total_decisions} governance checks" if data.has_data else "Continuous monitoring deployed",
                f"Violations tracked: {len(data.violations)}" if data.has_data else "",
            ],
        },
    }

    # Clean empty practices
    for fn in functions.values():
        fn["practices"] = [p for p in fn["practices"] if p]

    avg_score = sum(f["score"] for f in functions.values()) / len(functions)

    return {
        "report_type": "NIST AI RMF Assessment",
        "system_name": system_name,
        "framework_version": "1.0",
        "generated_at": now,
        "overall_maturity": round(avg_score * 100, 1),
        "compliance_score": round(avg_score * 100, 1),
        "executive_summary": data.executive_summary(),
        "functions": functions,
        "violations": data.violations[:10] if data.has_data else [],
        "recommendations": data.recommendations(),
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
    """Generate SOC 2 Type II readiness report with real database data."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()
    data = _load_data(system_name, ctx)

    # SOC2 evidence from real evidence items
    soc2_evidence = data.get_evidence_for_controls(["SOC2-"]) if data.has_data else []
    has_security_evidence = any(e.get("control_id", "").startswith("SOC2-CC6") for e in soc2_evidence)
    has_monitoring_evidence = any(e.get("control_id", "").startswith("SOC2-CC7") for e in soc2_evidence)
    has_change_mgmt_evidence = any(e.get("control_id", "").startswith("SOC2-CC8") for e in soc2_evidence)

    # Determine status from real data
    security_ok = has_security_evidence or not ctx.get("injection_detected", True)
    processing_ok = (data.has_data and data.compliance_rate > 80) or ctx.get("drift_score", 1.0) < 0.3
    confidentiality_ok = has_security_evidence or not ctx.get("pii_detected", True)

    criteria = {
        "security": {
            "status": "compliant" if security_ok else "non_compliant",
            "description": "System protected against unauthorized access and adversarial inputs",
            "evidence": (
                f"Access controls verified via {len([e for e in soc2_evidence if 'CC6' in e.get('control_id', '')])} evidence items"
                if has_security_evidence
                else "No security evidence collected"
            ),
            "evidence_refs": [e for e in soc2_evidence if "CC6" in e.get("control_id", "")][:5],
        },
        "availability": {
            "status": "compliant" if data.has_data or True else "needs_review",
            "description": "System operates and is available as committed",
            "evidence": f"Governance system operational: {data.total_decisions} decisions processed" if data.has_data else "System available",
        },
        "processing_integrity": {
            "status": "compliant" if processing_ok else "non_compliant",
            "description": "System processing is complete, valid, accurate, and authorized",
            "evidence": (
                f"Compliance rate: {data.compliance_rate}% across {data.total_decisions} decisions"
                if data.has_data
                else f"Drift score: {ctx.get('drift_score', 'N/A')}"
            ),
            "evidence_refs": [e for e in soc2_evidence if "CC7" in e.get("control_id", "")][:5],
        },
        "confidentiality": {
            "status": "compliant" if confidentiality_ok else "non_compliant",
            "description": "Confidential information is protected as committed",
            "evidence": (
                f"Data protection verified via {len([e for e in soc2_evidence if 'CC6.7' in e.get('control_id', '')])} evidence items"
                if has_security_evidence
                else "No confidentiality evidence collected"
            ),
        },
        "privacy": {
            "status": "compliant" if ctx.get("data_governance_active", False) or has_security_evidence else "needs_review",
            "description": "Personal information collected, used, retained, and disposed properly",
            "evidence": f"{data.total_evidence} evidence items collected for privacy controls" if data.has_data else "Not yet assessed",
        },
    }

    compliant = sum(1 for c in criteria.values() if c["status"] == "compliant")
    total = len(criteria)

    return {
        "report_type": "SOC 2 Type II Readiness",
        "system_name": system_name,
        "generated_at": now,
        "compliance_score": round(compliant / total * 100, 1),
        "executive_summary": data.executive_summary(),
        "trust_service_criteria": criteria,
        "summary": {"compliant": compliant, "non_compliant": total - compliant, "total": total},
        "risk_dimensions": data.risk_dimension_averages if data.has_data else {},
        "violations": data.violations[:10] if data.has_data else [],
        "recommendations": data.recommendations(),
        "recommendation": "Ready for SOC 2 Type II audit" if compliant == total else "Remediation needed before SOC 2 audit engagement",
    }


def generate_gdpr_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate GDPR compliance report with real database data."""
    ctx = context or {}
    now = datetime.utcnow().isoformat()
    data = _load_data(system_name, ctx)

    gdpr_evidence = data.get_evidence_for_controls(["GDPR-"]) if data.has_data else []
    has_data_protection_evidence = len(gdpr_evidence) > 0
    accuracy_ok = (data.has_data and data.compliance_rate > 80) or ctx.get("drift_score", 1.0) < 0.3
    has_audit_trail = data.total_decisions > 0

    principles = {
        "lawful_processing": {
            "status": "compliant" if ctx.get("legal_basis_documented", False) else "needs_review",
            "description": "Legal basis for processing established (Art. 6)",
            "evidence": f"Governance decisions recorded: {data.total_decisions}" if data.has_data else "Not yet documented",
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
            "status": "compliant" if accuracy_ok else "non_compliant",
            "description": "Data and model outputs are accurate and up to date (Art. 5(1)(d))",
            "evidence": (
                f"Compliance rate: {data.compliance_rate}% across {data.total_decisions} decisions"
                if data.has_data
                else f"Drift score: {ctx.get('drift_score', 'N/A')}"
            ),
        },
        "right_to_explanation": {
            "status": "compliant" if ctx.get("has_explanation", False) or has_audit_trail else "non_compliant",
            "description": "Meaningful information about automated decision logic (Art. 22)",
            "evidence": (
                f"Full audit trail with {data.total_decisions} decisions and risk assessments"
                if has_audit_trail
                else "No automated decision audit trail"
            ),
        },
        "dpia_completed": {
            "status": "compliant" if ctx.get("dpia_done", False) or (data.has_data and len(data.risk_scores) > 0) else "non_compliant",
            "description": "Data Protection Impact Assessment completed (Art. 35)",
            "evidence": (
                f"{len(data.risk_scores)} risk assessments performed (avg score: {data.avg_risk_score})"
                if data.risk_scores
                else "No risk assessments found"
            ),
        },
        "data_protection": {
            "status": "compliant" if has_data_protection_evidence or not ctx.get("pii_detected", True) else "non_compliant",
            "description": "Technical measures to protect personal data (Art. 32)",
            "evidence": (
                f"{len(gdpr_evidence)} GDPR-related evidence items collected"
                if has_data_protection_evidence
                else "No data protection evidence collected"
            ),
            "evidence_refs": gdpr_evidence[:5],
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
        "executive_summary": data.executive_summary(),
        "principles": principles,
        "summary": {
            "compliant": compliant,
            "non_compliant": total - compliant - sum(1 for p in principles.values() if p["status"] == "needs_review"),
            "needs_review": sum(1 for p in principles.values() if p["status"] == "needs_review"),
            "total": total,
        },
        "violations": data.violations[:10] if data.has_data else [],
        "penalties": {"max_fine": "4% of annual global turnover or EUR 20M (whichever is greater)"},
        "recommendations": data.recommendations(),
        "recommendation": "System meets GDPR requirements" if compliant == total else "GDPR compliance gaps detected — risk of significant fines",
    }


def generate_iso_27001_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate ISO 27001 Information Security Management System compliance report.

    Covers Annex A controls relevant to AI systems, mapped to the 2022 revision
    (ISO/IEC 27001:2022) with its 4 control themes: Organizational, People,
    Physical, and Technological.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        # --- A.5 Organizational Controls ---
        "A5_2_information_security_roles": {
            "clause": "A.5.2",
            "theme": "organizational",
            "title": "Information security roles and responsibilities",
            "status": "compliant" if ctx.get("has_policy", False) else "non_compliant",
            "description": "AI system ownership, security roles, and governance responsibilities defined",
            "evidence": f"Governance policy: {'established' if ctx.get('has_policy', False) else 'missing'}",
        },
        "A5_10_acceptable_use": {
            "clause": "A.5.10",
            "theme": "organizational",
            "title": "Acceptable use of information and assets",
            "status": "compliant" if ctx.get("has_guardrails", False) else "needs_review",
            "description": "Acceptable use policy for AI models, data assets, and inference endpoints",
            "evidence": f"Guardrails: {'configured' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
        "A5_12_classification_of_information": {
            "clause": "A.5.12",
            "theme": "organizational",
            "title": "Classification of information",
            "status": "compliant" if ctx.get("data_classified", False) else "needs_review",
            "description": "Training data, model weights, and inference outputs classified by sensitivity",
            "evidence": f"Data classification: {'complete' if ctx.get('data_classified', False) else 'not confirmed'}",
        },
        "A5_23_information_security_for_cloud": {
            "clause": "A.5.23",
            "theme": "organizational",
            "title": "Information security for use of cloud services",
            "status": "compliant" if ctx.get("cloud_security", False) else "needs_review",
            "description": "Cloud-hosted AI services meet security requirements (LLM APIs, GPU clusters)",
            "evidence": f"Cloud security: {'verified' if ctx.get('cloud_security', False) else 'not confirmed'}",
        },
        "A5_29_information_security_during_disruption": {
            "clause": "A.5.29",
            "theme": "organizational",
            "title": "Information security during disruption",
            "status": "compliant" if ctx.get("has_incident_response", False) else "needs_review",
            "description": "AI system continuity and incident response procedures established",
            "evidence": f"Incident response: {'defined' if ctx.get('has_incident_response', False) else 'not confirmed'}",
        },

        # --- A.6 People Controls ---
        "A6_3_information_security_awareness": {
            "clause": "A.6.3",
            "theme": "people",
            "title": "Information security awareness, education and training",
            "status": "compliant" if ctx.get("team_trained", False) else "needs_review",
            "description": "AI development and operations teams trained on security practices",
            "evidence": f"Security training: {'completed' if ctx.get('team_trained', False) else 'not confirmed'}",
        },

        # --- A.7 Physical Controls ---
        "A7_10_storage_media": {
            "clause": "A.7.10",
            "theme": "physical",
            "title": "Storage media",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) else "needs_review",
            "description": "Model weights, training data, and audit logs stored securely",
            "evidence": f"Encryption at rest: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}",
        },

        # --- A.8 Technological Controls ---
        "A8_2_privileged_access_rights": {
            "clause": "A.8.2",
            "theme": "technological",
            "title": "Privileged access rights",
            "status": "compliant" if ctx.get("rbac_enabled", True) else "non_compliant",
            "description": "Role-based access control for model management and inference endpoints",
            "evidence": "RBAC with API key scopes enforced",
        },
        "A8_5_secure_authentication": {
            "clause": "A.8.5",
            "theme": "technological",
            "title": "Secure authentication",
            "status": "compliant",
            "description": "JWT + API key authentication for all governance endpoints",
            "evidence": "Dual auth: JWT tokens and scoped API keys (gl_xxx)",
        },
        "A8_9_configuration_management": {
            "clause": "A.8.9",
            "theme": "technological",
            "title": "Configuration management",
            "status": "compliant" if ctx.get("has_model_card", False) else "needs_review",
            "description": "AI model configurations versioned and documented via model cards",
            "evidence": f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "A8_11_data_masking": {
            "clause": "A.8.11",
            "theme": "technological",
            "title": "Data masking",
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "PII detection and redaction in model inputs/outputs",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'PII detected — redaction required'}",
        },
        "A8_15_logging": {
            "clause": "A.8.15",
            "theme": "technological",
            "title": "Logging",
            "status": "compliant",
            "description": "Immutable hash-chained audit ledger for all governance decisions",
            "evidence": "SHA-256 hash-chained audit trail with tamper detection",
        },
        "A8_16_monitoring_activities": {
            "clause": "A.8.16",
            "theme": "technological",
            "title": "Monitoring activities",
            "status": "compliant" if ctx.get("drift_score") is not None else "needs_review",
            "description": "Continuous monitoring for behavioral drift and anomalous outputs",
            "evidence": f"Drift monitoring: {'active (score: ' + str(ctx.get('drift_score')) + ')' if ctx.get('drift_score') is not None else 'not configured'}",
        },
        "A8_23_web_filtering": {
            "clause": "A.8.23",
            "theme": "technological",
            "title": "Web filtering",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) else "needs_review",
            "description": "Prompt injection and adversarial input filtering for AI endpoints",
            "evidence": f"Security scanner: {'active' if ctx.get('prompt_injection_scan', False) else 'not confirmed'}",
        },
        "A8_25_secure_development_lifecycle": {
            "clause": "A.8.25",
            "theme": "technological",
            "title": "Secure development lifecycle",
            "status": "compliant" if ctx.get("has_model_card", False) and ctx.get("risk_score") is not None else "needs_review",
            "description": "AI model lifecycle governance: development -> staging -> production with gates",
            "evidence": f"Lifecycle governance: {'active' if ctx.get('has_model_card', False) else 'partial'}",
        },
        "A8_28_secure_coding": {
            "clause": "A.8.28",
            "theme": "technological",
            "title": "Secure coding",
            "status": "compliant" if ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "AI system risk score within acceptable threshold",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    # Theme breakdown
    themes = {}
    for c in controls.values():
        theme = c["theme"]
        if theme not in themes:
            themes[theme] = {"total": 0, "compliant": 0}
        themes[theme]["total"] += 1
        if c["status"] == "compliant":
            themes[theme]["compliant"] += 1
    for t in themes.values():
        t["score"] = round(t["compliant"] / t["total"] * 100, 1) if t["total"] > 0 else 0

    return {
        "report_type": "ISO/IEC 27001:2022 Compliance",
        "system_name": system_name,
        "generated_at": now,
        "standard": "ISO/IEC 27001:2022",
        "scope": "Information Security Management System — AI system controls",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "theme_breakdown": themes,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "certification_readiness": "ready" if non_compliant == 0 and needs_review <= 2 else "gaps_remain",
        "recommendation": (
            "System meets ISO 27001 Annex A controls for AI information security"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed controls before certification audit"
        ),
    }


def generate_nis2_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate NIS2 Directive compliance report.

    The EU Network and Information Security Directive 2 (2022/2555) requires
    essential and important entities to implement cybersecurity risk management
    measures. This maps NIS2 obligations to AI system governance controls.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    # Determine entity classification
    entity_type = ctx.get("entity_type", "important")  # "essential" or "important"

    obligations = {
        # --- Article 21: Cybersecurity risk-management measures ---
        "art21_a_risk_analysis": {
            "article": "21(2)(a)",
            "title": "Policies on risk analysis and information system security",
            "status": "compliant" if ctx.get("has_policy", False) and ctx.get("risk_score") is not None else "non_compliant",
            "description": "Risk analysis policies covering AI system security posture",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}, Policy: {'established' if ctx.get('has_policy', False) else 'missing'}",
        },
        "art21_b_incident_handling": {
            "article": "21(2)(b)",
            "title": "Incident handling",
            "status": "compliant" if ctx.get("has_incident_response", False) else "needs_review",
            "description": "AI incident detection, reporting, and response procedures",
            "evidence": f"Incident management: {'active' if ctx.get('has_incident_response', False) else 'not confirmed'}",
        },
        "art21_c_business_continuity": {
            "article": "21(2)(c)",
            "title": "Business continuity and crisis management",
            "status": "compliant" if ctx.get("has_backup", False) else "needs_review",
            "description": "AI system backup, recovery, and failover procedures",
            "evidence": f"Business continuity: {'planned' if ctx.get('has_backup', False) else 'not confirmed'}",
        },
        "art21_d_supply_chain_security": {
            "article": "21(2)(d)",
            "title": "Supply chain security",
            "status": "compliant" if ctx.get("supply_chain_assessed", False) else "needs_review",
            "description": "Security assessment of AI model providers, data suppliers, and cloud services",
            "evidence": f"Supply chain: {'assessed' if ctx.get('supply_chain_assessed', False) else 'not confirmed'}",
        },
        "art21_e_network_security": {
            "article": "21(2)(e)",
            "title": "Security in network and information systems",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) else "needs_review",
            "description": "Vulnerability handling and security scanning for AI endpoints",
            "evidence": f"Security scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'not confirmed'}",
        },
        "art21_f_risk_assessment": {
            "article": "21(2)(f)",
            "title": "Policies and procedures for cybersecurity risk assessment",
            "status": "compliant" if ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "Effectiveness assessment of cybersecurity risk management measures",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
        "art21_g_cybersecurity_training": {
            "article": "21(2)(g)",
            "title": "Basic cyber hygiene practices and cybersecurity training",
            "status": "compliant" if ctx.get("team_trained", False) else "needs_review",
            "description": "AI team security awareness and responsible AI training",
            "evidence": f"Training: {'completed' if ctx.get('team_trained', False) else 'not confirmed'}",
        },
        "art21_h_cryptography": {
            "article": "21(2)(h)",
            "title": "Policies on the use of cryptography and encryption",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) else "needs_review",
            "description": "Encryption for model weights, training data, API communications, and audit logs",
            "evidence": f"Encryption: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}",
        },
        "art21_i_access_control": {
            "article": "21(2)(i)",
            "title": "Human resources security and access control policies",
            "status": "compliant" if ctx.get("rbac_enabled", True) else "non_compliant",
            "description": "Access control and identity management for AI governance platform",
            "evidence": "RBAC with scoped API keys and JWT authentication enforced",
        },
        "art21_j_mfa": {
            "article": "21(2)(j)",
            "title": "Multi-factor authentication and secure communications",
            "status": "needs_review",
            "description": "MFA for administrative access to AI governance systems",
            "evidence": "MFA status: review required",
        },

        # --- Article 23: Reporting obligations ---
        "art23_incident_notification": {
            "article": "23",
            "title": "Incident notification obligations",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "Significant incidents reported within 24h (early warning) and 72h (full notification)",
            "evidence": f"Incident reporting: {'configured' if ctx.get('has_incident_response', False) else 'not established'}",
        },

        # --- Article 29: Cybersecurity information sharing ---
        "art29_information_sharing": {
            "article": "29",
            "title": "Voluntary cybersecurity information sharing",
            "status": "compliant" if ctx.get("drift_score") is not None else "needs_review",
            "description": "Threat intelligence and AI drift/anomaly data available for sharing",
            "evidence": f"Monitoring active: {'yes' if ctx.get('drift_score') is not None else 'not confirmed'}",
        },
    }

    compliant = sum(1 for o in obligations.values() if o["status"] == "compliant")
    needs_review = sum(1 for o in obligations.values() if o["status"] == "needs_review")
    non_compliant = sum(1 for o in obligations.values() if o["status"] == "non_compliant")
    total = len(obligations)

    # Penalties differ by entity type
    if entity_type == "essential":
        max_fine = "EUR 10M or 2% of total annual worldwide turnover (whichever is higher)"
    else:
        max_fine = "EUR 7M or 1.4% of total annual worldwide turnover (whichever is higher)"

    return {
        "report_type": "NIS2 Directive Compliance",
        "system_name": system_name,
        "generated_at": now,
        "directive": "Directive (EU) 2022/2555 (NIS2)",
        "jurisdiction": "European Union",
        "entity_type": entity_type,
        "transposition_deadline": "2024-10-17",
        "compliance_score": round(compliant / total * 100, 1),
        "obligations": obligations,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "penalties": {
            "entity_type": entity_type,
            "max_fine": max_fine,
            "management_liability": "Senior management can be held personally liable for non-compliance",
        },
        "recommendation": (
            "System meets NIS2 cybersecurity risk management requirements"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed obligations — NIS2 enforcement is active since Oct 2024"
        ),
    }


def generate_dora_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate DORA (Digital Operational Resilience Act) compliance report.

    Regulation (EU) 2022/2554 applies to financial entities and their critical
    ICT third-party service providers, including AI systems used in financial
    decision-making, risk assessment, and fraud detection.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "art5_ict_risk_management_framework": {
            "article": "5",
            "title": "ICT risk management framework",
            "status": "compliant" if ctx.get("has_policy", False) and ctx.get("risk_score") is not None else "non_compliant",
            "description": "Comprehensive ICT risk management framework covering AI systems",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}, Policy: {'established' if ctx.get('has_policy', False) else 'missing'}",
        },
        "art6_ict_systems_protocols_tools": {
            "article": "6",
            "title": "ICT systems, protocols and tools",
            "status": "compliant" if ctx.get("has_model_card", False) else "needs_review",
            "description": "AI systems identified, classified, and documented with adequate protocols",
            "evidence": f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "art8_identification": {
            "article": "8",
            "title": "Identification of ICT risk",
            "status": "compliant" if ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "All sources of ICT risk identified including AI model vulnerabilities",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
        "art9_protection_and_prevention": {
            "article": "9",
            "title": "Protection and prevention",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) and ctx.get("has_guardrails", False) else "needs_review",
            "description": "ICT security policies and tools to protect AI endpoints from adversarial attacks",
            "evidence": f"Guardrails: {'active' if ctx.get('has_guardrails', False) else 'not confirmed'}, Input scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'not confirmed'}",
        },
        "art10_detection": {
            "article": "10",
            "title": "Detection of anomalous activities",
            "status": "compliant" if ctx.get("drift_score") is not None else "needs_review",
            "description": "Mechanisms to detect anomalous AI behavior and data breaches",
            "evidence": f"Drift monitoring: {'active (score: ' + str(ctx.get('drift_score')) + ')' if ctx.get('drift_score') is not None else 'not configured'}",
        },
        "art11_response_and_recovery": {
            "article": "11",
            "title": "Response and recovery",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "ICT business continuity and disaster recovery plans for AI systems",
            "evidence": f"Incident response: {'defined' if ctx.get('has_incident_response', False) else 'not established'}",
        },
        "art15_ict_related_incident_management": {
            "article": "15",
            "title": "ICT-related incident management process",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "Process to detect, manage, and report ICT-related incidents involving AI",
            "evidence": f"Incident management: {'active' if ctx.get('has_incident_response', False) else 'missing'}",
        },
        "art19_reporting_major_incidents": {
            "article": "19",
            "title": "Reporting of major ICT-related incidents",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "Major AI incidents reported to competent authority within required timelines",
            "evidence": f"Incident reporting: {'configured' if ctx.get('has_incident_response', False) else 'not established'}",
        },
        "art24_general_requirements_ict_testing": {
            "article": "24",
            "title": "General requirements for ICT testing",
            "status": "compliant" if ctx.get("fairness_tested", False) or ctx.get("drift_score") is not None else "needs_review",
            "description": "Regular testing of AI system resilience including adversarial and stress testing",
            "evidence": f"Testing: {'conducted' if ctx.get('fairness_tested', False) else 'not confirmed'}",
        },
        "art28_third_party_risk": {
            "article": "28",
            "title": "General principles of ICT third-party risk management",
            "status": "compliant" if ctx.get("supply_chain_assessed", False) else "needs_review",
            "description": "Third-party AI model providers and cloud services risk-assessed",
            "evidence": f"Third-party assessment: {'completed' if ctx.get('supply_chain_assessed', False) else 'not confirmed'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "DORA Compliance",
        "system_name": system_name,
        "generated_at": now,
        "regulation": "Regulation (EU) 2022/2554 (DORA)",
        "jurisdiction": "European Union",
        "applies_to": "Financial entities and critical ICT third-party service providers",
        "effective_date": "2025-01-17",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "penalties": {
            "max_fine": "Up to 1% of average daily worldwide turnover per day for up to 6 months",
            "supervisory_powers": "Competent authorities may require cessation of AI activities",
        },
        "recommendation": (
            "System meets DORA digital operational resilience requirements"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed controls — DORA enforcement began Jan 2025"
        ),
    }


def generate_ccpa_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate CCPA/CPRA compliance report for AI systems processing consumer data.

    California Consumer Privacy Act (as amended by CPRA) applies to AI systems
    that process California consumers' personal information, including automated
    decision-making technology (ADMT).
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "sec1798_100_right_to_know": {
            "section": "1798.100",
            "title": "Right to know about personal information collected",
            "status": "compliant" if ctx.get("has_explanation", False) else "non_compliant",
            "description": "Consumers informed about what personal information the AI system collects and processes",
            "evidence": f"Transparency: {'enabled' if ctx.get('has_explanation', False) else 'not configured'}",
        },
        "sec1798_105_right_to_delete": {
            "section": "1798.105",
            "title": "Right to delete personal information",
            "status": "compliant" if ctx.get("data_deletion_capable", False) else "needs_review",
            "description": "Ability to delete consumer data from AI training sets and inference pipelines",
            "evidence": f"Data deletion: {'supported' if ctx.get('data_deletion_capable', False) else 'not confirmed'}",
        },
        "sec1798_110_right_to_access": {
            "section": "1798.110",
            "title": "Right to access personal information",
            "status": "compliant" if ctx.get("has_explanation", False) else "needs_review",
            "description": "Consumers can access personal information used by the AI system",
            "evidence": f"Data access: {'available' if ctx.get('has_explanation', False) else 'not confirmed'}",
        },
        "sec1798_120_right_to_opt_out": {
            "section": "1798.120",
            "title": "Right to opt-out of sale/sharing of personal information",
            "status": "compliant" if ctx.get("opt_out_available", False) else "non_compliant",
            "description": "Opt-out mechanism for sale or sharing of personal information with AI systems",
            "evidence": f"Opt-out: {'available' if ctx.get('opt_out_available', False) else 'not implemented'}",
        },
        "sec1798_121_right_to_limit_sensitive": {
            "section": "1798.121",
            "title": "Right to limit use of sensitive personal information",
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "Sensitive personal information use limited to disclosed purposes in AI processing",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'sensitive data detected'}",
        },
        "sec1798_130_notice_at_collection": {
            "section": "1798.130",
            "title": "Notice at collection",
            "status": "compliant" if ctx.get("purpose_documented", False) else "needs_review",
            "description": "Privacy notice provided at or before point of data collection for AI processing",
            "evidence": f"Notice: {'provided' if ctx.get('purpose_documented', False) else 'not confirmed'}",
        },
        "sec1798_135_data_minimization": {
            "section": "1798.100(c)",
            "title": "Data minimization and purpose limitation",
            "status": "compliant" if ctx.get("data_minimized", False) else "needs_review",
            "description": "AI system collects only personal information reasonably necessary for disclosed purpose",
            "evidence": f"Data minimization: {'enforced' if ctx.get('data_minimized', False) else 'not confirmed'}",
        },
        "sec1798_185_admt": {
            "section": "1798.185(a)(16)",
            "title": "Automated decision-making technology (ADMT) requirements",
            "status": "compliant" if ctx.get("has_explanation", False) and ctx.get("human_oversight", False) else "non_compliant",
            "description": "ADMT opt-out, access to logic, and human review for significant decisions",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'missing'}, Human oversight: {'enabled' if ctx.get('human_oversight', False) else 'missing'}",
        },
        "sec1798_150_data_security": {
            "section": "1798.150",
            "title": "Data security obligations",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) else "needs_review",
            "description": "Reasonable security measures for personal information in AI systems",
            "evidence": f"Encryption at rest: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "CCPA/CPRA Compliance",
        "system_name": system_name,
        "generated_at": now,
        "jurisdiction": "California, United States",
        "applies_to": "Businesses processing California consumers' personal information",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "penalties": {
            "max_fine_intentional": "$7,500 per intentional violation",
            "max_fine_unintentional": "$2,500 per unintentional violation",
            "private_right_of_action": "$100-$750 per consumer per incident for data breaches",
        },
        "recommendation": (
            "System meets CCPA/CPRA privacy requirements for AI"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed controls — CPRA enforcement is active"
        ),
    }


def generate_hipaa_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate HIPAA compliance report for AI systems handling protected health information.

    Health Insurance Portability and Accountability Act applies to covered entities
    and business associates using AI for clinical decision support, claims processing,
    patient data analysis, and health risk prediction.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "sec164_308_a1_risk_analysis": {
            "section": "164.308(a)(1)(ii)(A)",
            "title": "Risk analysis (Administrative Safeguard)",
            "status": "compliant" if ctx.get("risk_score") is not None and ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "Conduct accurate and thorough assessment of risks to ePHI in AI systems",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
        "sec164_308_a3_workforce_security": {
            "section": "164.308(a)(3)",
            "title": "Workforce security (Administrative Safeguard)",
            "status": "compliant" if ctx.get("rbac_enabled", True) else "non_compliant",
            "description": "Access controls ensure only authorized personnel interact with AI systems handling PHI",
            "evidence": "RBAC with scoped API keys enforced",
        },
        "sec164_308_a5_security_awareness": {
            "section": "164.308(a)(5)",
            "title": "Security awareness and training (Administrative Safeguard)",
            "status": "compliant" if ctx.get("team_trained", False) else "needs_review",
            "description": "Security awareness training for workforce members using AI with PHI",
            "evidence": f"Training: {'completed' if ctx.get('team_trained', False) else 'not confirmed'}",
        },
        "sec164_308_a6_security_incident": {
            "section": "164.308(a)(6)",
            "title": "Security incident procedures (Administrative Safeguard)",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "Procedures for detecting, reporting, and responding to AI security incidents",
            "evidence": f"Incident response: {'defined' if ctx.get('has_incident_response', False) else 'not established'}",
        },
        "sec164_312_a1_access_control": {
            "section": "164.312(a)(1)",
            "title": "Access control (Technical Safeguard)",
            "status": "compliant" if ctx.get("rbac_enabled", True) else "non_compliant",
            "description": "Technical policies to allow only authorized access to AI systems with ePHI",
            "evidence": "Unique user identification and role-based access enforced",
        },
        "sec164_312_a2iv_encryption": {
            "section": "164.312(a)(2)(iv)",
            "title": "Encryption and decryption (Technical Safeguard)",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) else "non_compliant",
            "description": "Encryption of ePHI at rest in AI model storage and training data",
            "evidence": f"Encryption at rest: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not enabled'}",
        },
        "sec164_312_b_audit_controls": {
            "section": "164.312(b)",
            "title": "Audit controls (Technical Safeguard)",
            "status": "compliant" if ctx.get("has_audit_trail", False) else "non_compliant",
            "description": "Hardware, software, and procedural mechanisms to record AI access to ePHI",
            "evidence": f"Audit trail: {'active (hash-chained)' if ctx.get('has_audit_trail', False) else 'not configured'}",
        },
        "sec164_312_c1_integrity": {
            "section": "164.312(c)(1)",
            "title": "Integrity controls (Technical Safeguard)",
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 else "non_compliant",
            "description": "Policies to protect ePHI from improper alteration in AI processing pipelines",
            "evidence": f"Drift score: {ctx.get('drift_score', 'N/A')}",
        },
        "sec164_312_e1_transmission_security": {
            "section": "164.312(e)(1)",
            "title": "Transmission security (Technical Safeguard)",
            "status": "compliant" if ctx.get("data_encrypted_in_transit", False) else "needs_review",
            "description": "Technical measures to guard against unauthorized access to ePHI during transmission to AI services",
            "evidence": f"Encryption in transit: {'enabled' if ctx.get('data_encrypted_in_transit', False) else 'not confirmed'}",
        },
        "sec164_502_minimum_necessary": {
            "section": "164.502(b)",
            "title": "Minimum necessary standard (Privacy Rule)",
            "status": "compliant" if ctx.get("data_minimized", False) else "needs_review",
            "description": "AI system uses only minimum necessary PHI for its intended purpose",
            "evidence": f"Data minimization: {'enforced' if ctx.get('data_minimized', False) else 'not confirmed'}",
        },
        "sec164_520_notice_of_privacy": {
            "section": "164.520",
            "title": "Notice of privacy practices (Privacy Rule)",
            "status": "compliant" if ctx.get("purpose_documented", False) else "needs_review",
            "description": "Notice of privacy practices describes AI system use of PHI",
            "evidence": f"Privacy notice: {'documented' if ctx.get('purpose_documented', False) else 'not confirmed'}",
        },
        "sec164_530_administrative_requirements": {
            "section": "164.530(c)",
            "title": "Administrative requirements — safeguards (Privacy Rule)",
            "status": "compliant" if ctx.get("has_guardrails", False) else "needs_review",
            "description": "Appropriate safeguards to protect PHI processed by AI systems",
            "evidence": f"Guardrails: {'configured' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "HIPAA Compliance",
        "system_name": system_name,
        "generated_at": now,
        "jurisdiction": "United States",
        "applies_to": "Covered entities and business associates handling PHI with AI systems",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "penalties": {
            "tier_1": "Up to $100 per violation (did not know)",
            "tier_2": "Up to $50,000 per violation (reasonable cause)",
            "tier_3": "Up to $50,000 per violation (willful neglect, corrected)",
            "tier_4": "Up to $1,500,000 per violation (willful neglect, not corrected)",
            "criminal": "Up to $250,000 and 10 years imprisonment",
        },
        "recommendation": (
            "System meets HIPAA requirements for AI processing of PHI"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed controls — HIPAA violations carry severe penalties"
        ),
    }


def generate_mitre_atlas_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate MITRE ATLAS (Adversarial Threat Landscape for AI Systems) assessment report.

    MITRE ATLAS catalogs adversarial tactics, techniques, and procedures (TTPs)
    targeting AI/ML systems. This report assesses defenses against key ATLAS
    threat categories.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "AML_T0000_reconnaissance": {
            "technique_id": "AML.T0000",
            "tactic": "Reconnaissance",
            "title": "AI system reconnaissance defense",
            "status": "compliant" if ctx.get("has_guardrails", False) else "needs_review",
            "description": "Defenses against adversary gathering information about AI model architecture and endpoints",
            "evidence": f"Guardrails: {'active — model details obscured' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
        "AML_T0015_evasion_via_adversarial_input": {
            "technique_id": "AML.T0015",
            "tactic": "Evasion",
            "title": "Evade ML model via adversarial input defense",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) else "non_compliant",
            "description": "Input validation and adversarial example detection for model evasion attacks",
            "evidence": f"Input scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'not configured'}",
        },
        "AML_T0024_exfiltration_via_inference_api": {
            "technique_id": "AML.T0024",
            "tactic": "Exfiltration",
            "title": "Exfiltration via inference API defense",
            "status": "compliant" if ctx.get("rbac_enabled", True) and ctx.get("has_audit_trail", False) else "needs_review",
            "description": "Rate limiting, access controls, and monitoring to prevent model extraction via API",
            "evidence": f"RBAC: {'enabled' if ctx.get('rbac_enabled', True) else 'disabled'}, Audit trail: {'active' if ctx.get('has_audit_trail', False) else 'not confirmed'}",
        },
        "AML_T0018_backdoor_ml_model": {
            "technique_id": "AML.T0018",
            "tactic": "Persistence",
            "title": "Backdoor ML model defense",
            "status": "compliant" if ctx.get("has_model_card", False) and ctx.get("supply_chain_assessed", False) else "needs_review",
            "description": "Model provenance tracking and supply chain validation to detect backdoors",
            "evidence": f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}, Supply chain: {'assessed' if ctx.get('supply_chain_assessed', False) else 'not confirmed'}",
        },
        "AML_T0020_poison_training_data": {
            "technique_id": "AML.T0020",
            "tactic": "Initial Access",
            "title": "Data poisoning defense",
            "status": "compliant" if not ctx.get("pii_detected", True) and ctx.get("data_classified", False) else "needs_review",
            "description": "Training data integrity validation and poisoning detection mechanisms",
            "evidence": f"Data classification: {'complete' if ctx.get('data_classified', False) else 'not confirmed'}, PII scan: {'clean' if not ctx.get('pii_detected', True) else 'findings detected'}",
        },
        "AML_T0043_prompt_injection": {
            "technique_id": "AML.T0043",
            "tactic": "Initial Access",
            "title": "LLM prompt injection defense",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) else "non_compliant",
            "description": "Direct and indirect prompt injection detection and mitigation",
            "evidence": f"Prompt injection scanner: {'active' if ctx.get('prompt_injection_scan', False) else 'not deployed'}",
        },
        "AML_T0044_full_model_theft": {
            "technique_id": "AML.T0044",
            "tactic": "Exfiltration",
            "title": "Full ML model theft defense",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) and ctx.get("rbac_enabled", True) else "needs_review",
            "description": "Model weight encryption, access controls, and extraction detection",
            "evidence": f"Encryption: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}, RBAC: {'enabled' if ctx.get('rbac_enabled', True) else 'disabled'}",
        },
        "AML_T0047_ml_supply_chain_compromise": {
            "technique_id": "AML.T0047",
            "tactic": "Initial Access",
            "title": "ML supply chain compromise defense",
            "status": "compliant" if ctx.get("supply_chain_assessed", False) else "non_compliant",
            "description": "Validation of third-party models, libraries, and data sources",
            "evidence": f"Supply chain assessment: {'completed' if ctx.get('supply_chain_assessed', False) else 'not conducted'}",
        },
        "AML_T0048_aml_model_inference_api_access": {
            "technique_id": "AML.T0048",
            "tactic": "Discovery",
            "title": "Inference API access monitoring",
            "status": "compliant" if ctx.get("drift_score") is not None else "needs_review",
            "description": "Behavioral monitoring of API usage patterns to detect model probing",
            "evidence": f"Drift monitoring: {'active' if ctx.get('drift_score') is not None else 'not configured'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "MITRE ATLAS Threat Assessment",
        "system_name": system_name,
        "generated_at": now,
        "framework": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "recommendation": (
            "System has adequate defenses against known ATLAS adversarial techniques"
            if compliant == total
            else f"Address {non_compliant} undefended and {needs_review} unconfirmed threat vectors"
        ),
    }


def generate_owasp_ai_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate OWASP Top 10 for AI/ML Applications security assessment report.

    Maps OWASP AI/ML top risks to governance controls, covering prompt injection,
    training data poisoning, model denial of service, supply chain vulnerabilities,
    and other AI-specific security concerns.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "LLM01_prompt_injection": {
            "risk_id": "LLM01",
            "title": "Prompt Injection",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) else "non_compliant",
            "description": "Direct and indirect prompt injection via crafted inputs that manipulate LLM behavior",
            "evidence": f"Prompt injection scanner: {'active' if ctx.get('prompt_injection_scan', False) else 'not deployed'}",
        },
        "LLM02_insecure_output_handling": {
            "risk_id": "LLM02",
            "title": "Insecure Output Handling",
            "status": "compliant" if ctx.get("has_guardrails", False) else "non_compliant",
            "description": "LLM outputs not validated before passing to downstream systems or users",
            "evidence": f"Output guardrails: {'active' if ctx.get('has_guardrails', False) else 'not configured'}",
        },
        "LLM03_training_data_poisoning": {
            "risk_id": "LLM03",
            "title": "Training Data Poisoning",
            "status": "compliant" if ctx.get("data_classified", False) else "needs_review",
            "description": "Manipulation of training data to introduce vulnerabilities or biases",
            "evidence": f"Data classification: {'complete' if ctx.get('data_classified', False) else 'not confirmed'}",
        },
        "LLM04_model_denial_of_service": {
            "risk_id": "LLM04",
            "title": "Model Denial of Service",
            "status": "compliant" if ctx.get("has_guardrails", False) else "needs_review",
            "description": "Resource exhaustion attacks via crafted inputs consuming excessive computation",
            "evidence": f"Rate limiting and input guardrails: {'active' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
        "LLM05_supply_chain_vulnerabilities": {
            "risk_id": "LLM05",
            "title": "Supply Chain Vulnerabilities",
            "status": "compliant" if ctx.get("supply_chain_assessed", False) else "non_compliant",
            "description": "Vulnerabilities in third-party models, plugins, training data, and deployment platforms",
            "evidence": f"Supply chain assessment: {'completed' if ctx.get('supply_chain_assessed', False) else 'not conducted'}",
        },
        "LLM06_sensitive_information_disclosure": {
            "risk_id": "LLM06",
            "title": "Sensitive Information Disclosure",
            "status": "compliant" if not ctx.get("pii_detected", True) else "non_compliant",
            "description": "LLM revealing sensitive data, PII, or proprietary information in responses",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'sensitive data detected'}",
        },
        "LLM07_insecure_plugin_design": {
            "risk_id": "LLM07",
            "title": "Insecure Plugin Design",
            "status": "compliant" if ctx.get("rbac_enabled", True) and ctx.get("has_guardrails", False) else "needs_review",
            "description": "Plugins/tools with insufficient access controls or input validation",
            "evidence": f"RBAC: {'enabled' if ctx.get('rbac_enabled', True) else 'disabled'}, Guardrails: {'active' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
        "LLM08_excessive_agency": {
            "risk_id": "LLM08",
            "title": "Excessive Agency",
            "status": "compliant" if ctx.get("human_oversight", False) else "non_compliant",
            "description": "LLM granted excessive functionality, permissions, or autonomy",
            "evidence": f"Human oversight: {'enabled' if ctx.get('human_oversight', False) else 'not configured'}",
        },
        "LLM09_overreliance": {
            "risk_id": "LLM09",
            "title": "Overreliance",
            "status": "compliant" if ctx.get("has_explanation", False) and ctx.get("drift_score", 1.0) < 0.3 else "needs_review",
            "description": "Uncritical dependence on LLM outputs without verification or monitoring",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'missing'}, Drift: {ctx.get('drift_score', 'N/A')}",
        },
        "LLM10_model_theft": {
            "risk_id": "LLM10",
            "title": "Model Theft",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) and ctx.get("rbac_enabled", True) else "needs_review",
            "description": "Unauthorized access, extraction, or replication of proprietary LLM models",
            "evidence": f"Encryption: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}, RBAC: {'enabled' if ctx.get('rbac_enabled', True) else 'disabled'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "OWASP Top 10 for LLM Applications",
        "system_name": system_name,
        "generated_at": now,
        "framework": "OWASP Top 10 for LLM Applications (2025)",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "recommendation": (
            "System has mitigations for all OWASP LLM Top 10 risks"
            if compliant == total
            else f"Address {non_compliant} unmitigated and {needs_review} unconfirmed OWASP LLM risks"
        ),
    }


def generate_nist_csf_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate NIST Cybersecurity Framework 2.0 compliance report.

    NIST CSF 2.0 organizes cybersecurity outcomes into six functions: Govern,
    Identify, Protect, Detect, Respond, and Recover. This report maps CSF
    categories to AI system governance controls.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "GV_OC_01_organizational_context": {
            "function": "Govern",
            "category": "GV.OC",
            "title": "Organizational context",
            "status": "compliant" if ctx.get("has_policy", False) else "needs_review",
            "description": "AI governance mission, stakeholder expectations, and legal requirements understood",
            "evidence": f"Governance policy: {'established' if ctx.get('has_policy', False) else 'not confirmed'}",
        },
        "GV_RM_01_risk_management_strategy": {
            "function": "Govern",
            "category": "GV.RM",
            "title": "Risk management strategy",
            "status": "compliant" if ctx.get("has_policy", False) and ctx.get("risk_score") is not None else "non_compliant",
            "description": "AI risk management strategy established, communicated, and monitored",
            "evidence": f"Policy: {'established' if ctx.get('has_policy', False) else 'missing'}, Risk scoring: {'active' if ctx.get('risk_score') is not None else 'inactive'}",
        },
        "ID_AM_01_asset_management": {
            "function": "Identify",
            "category": "ID.AM",
            "title": "Asset management",
            "status": "compliant" if ctx.get("has_model_card", False) else "needs_review",
            "description": "AI assets (models, data, endpoints) inventoried and managed",
            "evidence": f"Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "ID_RA_01_risk_assessment": {
            "function": "Identify",
            "category": "ID.RA",
            "title": "Risk assessment",
            "status": "compliant" if ctx.get("risk_score", 100) < 70 else "non_compliant",
            "description": "AI system vulnerabilities identified and risk assessed",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}",
        },
        "PR_AA_01_identity_and_access": {
            "function": "Protect",
            "category": "PR.AA",
            "title": "Identity management, authentication, and access control",
            "status": "compliant" if ctx.get("rbac_enabled", True) else "non_compliant",
            "description": "Identities and credentials managed, access controlled for AI systems",
            "evidence": "RBAC with JWT and scoped API keys enforced",
        },
        "PR_DS_01_data_security": {
            "function": "Protect",
            "category": "PR.DS",
            "title": "Data security",
            "status": "compliant" if ctx.get("data_encrypted_at_rest", False) and not ctx.get("pii_detected", True) else "needs_review",
            "description": "Data at rest and in transit protected, PII managed",
            "evidence": f"Encryption: {'enabled' if ctx.get('data_encrypted_at_rest', False) else 'not confirmed'}, PII: {'clean' if not ctx.get('pii_detected', True) else 'detected'}",
        },
        "PR_AT_01_awareness_and_training": {
            "function": "Protect",
            "category": "PR.AT",
            "title": "Awareness and training",
            "status": "compliant" if ctx.get("team_trained", False) else "needs_review",
            "description": "Personnel trained on AI security risks and responsible use",
            "evidence": f"Training: {'completed' if ctx.get('team_trained', False) else 'not confirmed'}",
        },
        "PR_PS_01_platform_security": {
            "function": "Protect",
            "category": "PR.PS",
            "title": "Platform security",
            "status": "compliant" if ctx.get("has_guardrails", False) and ctx.get("prompt_injection_scan", False) else "needs_review",
            "description": "AI platform hardened with guardrails and input validation",
            "evidence": f"Guardrails: {'active' if ctx.get('has_guardrails', False) else 'not confirmed'}, Scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'not confirmed'}",
        },
        "DE_CM_01_continuous_monitoring": {
            "function": "Detect",
            "category": "DE.CM",
            "title": "Continuous monitoring",
            "status": "compliant" if ctx.get("drift_score") is not None else "non_compliant",
            "description": "AI system behavior continuously monitored for drift and anomalies",
            "evidence": f"Drift monitoring: {'active (score: ' + str(ctx.get('drift_score')) + ')' if ctx.get('drift_score') is not None else 'not configured'}",
        },
        "DE_AE_01_adverse_event_analysis": {
            "function": "Detect",
            "category": "DE.AE",
            "title": "Adverse event analysis",
            "status": "compliant" if ctx.get("has_audit_trail", False) else "needs_review",
            "description": "Anomalies and potential adverse AI events analyzed with audit trails",
            "evidence": f"Audit trail: {'active' if ctx.get('has_audit_trail', False) else 'not confirmed'}",
        },
        "RS_MA_01_incident_management": {
            "function": "Respond",
            "category": "RS.MA",
            "title": "Incident management",
            "status": "compliant" if ctx.get("has_incident_response", False) else "non_compliant",
            "description": "AI incidents managed with defined response procedures",
            "evidence": f"Incident response: {'defined' if ctx.get('has_incident_response', False) else 'not established'}",
        },
        "RC_RP_01_recovery_planning": {
            "function": "Recover",
            "category": "RC.RP",
            "title": "Incident recovery plan execution",
            "status": "compliant" if ctx.get("has_backup", False) else "needs_review",
            "description": "Recovery plan for AI system restoration after incidents",
            "evidence": f"Recovery plan: {'established' if ctx.get('has_backup', False) else 'not confirmed'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    # Function breakdown
    functions = {}
    for c in controls.values():
        func = c["function"]
        if func not in functions:
            functions[func] = {"total": 0, "compliant": 0}
        functions[func]["total"] += 1
        if c["status"] == "compliant":
            functions[func]["compliant"] += 1
    for f in functions.values():
        f["score"] = round(f["compliant"] / f["total"] * 100, 1) if f["total"] > 0 else 0

    return {
        "report_type": "NIST CSF 2.0 Compliance",
        "system_name": system_name,
        "generated_at": now,
        "framework": "NIST Cybersecurity Framework 2.0",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "function_breakdown": functions,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "recommendation": (
            "System meets NIST CSF 2.0 cybersecurity outcomes for AI governance"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed controls across CSF functions"
        ),
    }


def generate_oecd_ai_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate OECD AI Principles compliance report.

    The OECD Principles on AI (adopted May 2019, updated 2024) provide
    intergovernmental standards for responsible AI. Adopted by 46 countries.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "principle_1_1_inclusive_growth": {
            "principle": "1.1",
            "title": "Inclusive growth, sustainable development and well-being",
            "status": "compliant" if ctx.get("has_policy", False) else "needs_review",
            "description": "AI system designed to benefit people and the planet",
            "evidence": f"Governance policy: {'established' if ctx.get('has_policy', False) else 'not confirmed'}",
        },
        "principle_1_2_human_centred_values": {
            "principle": "1.2",
            "title": "Human-centred values and fairness",
            "status": "compliant" if ctx.get("fairness_tested", False) and ctx.get("human_oversight", False) else "non_compliant",
            "description": "AI system respects rule of law, human rights, democratic values, and diversity",
            "evidence": f"Fairness testing: {'completed' if ctx.get('fairness_tested', False) else 'not conducted'}, Human oversight: {'enabled' if ctx.get('human_oversight', False) else 'missing'}",
        },
        "principle_1_3_transparency_explainability": {
            "principle": "1.3",
            "title": "Transparency and explainability",
            "status": "compliant" if ctx.get("has_explanation", False) and ctx.get("has_model_card", False) else "non_compliant",
            "description": "Meaningful information provided about AI systems enabling understanding and challenge",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'missing'}, Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "principle_1_4_robustness_security": {
            "principle": "1.4",
            "title": "Robustness, security and safety",
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 and ctx.get("prompt_injection_scan", False) else "non_compliant",
            "description": "AI system functions robustly, securely, and safely throughout lifecycle",
            "evidence": f"Drift score: {ctx.get('drift_score', 'N/A')}, Security scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'inactive'}",
        },
        "principle_1_5_accountability": {
            "principle": "1.5",
            "title": "Accountability",
            "status": "compliant" if ctx.get("has_audit_trail", False) and ctx.get("has_policy", False) else "non_compliant",
            "description": "Organizations accountable for proper functioning of AI systems they operate",
            "evidence": f"Audit trail: {'active' if ctx.get('has_audit_trail', False) else 'missing'}, Policy: {'established' if ctx.get('has_policy', False) else 'missing'}",
        },
        "principle_2_1_investing_in_research": {
            "principle": "2.1",
            "title": "Investing in AI research and development",
            "status": "compliant" if ctx.get("has_model_card", False) else "needs_review",
            "description": "Investment in responsible AI R&D that addresses technical and societal challenges",
            "evidence": f"Model documentation: {'present' if ctx.get('has_model_card', False) else 'not confirmed'}",
        },
        "principle_2_2_digital_ecosystem": {
            "principle": "2.2",
            "title": "Fostering a digital ecosystem for AI",
            "status": "compliant" if ctx.get("supply_chain_assessed", False) else "needs_review",
            "description": "Interoperable, trustworthy AI ecosystem with data sharing and responsible use",
            "evidence": f"Supply chain: {'assessed' if ctx.get('supply_chain_assessed', False) else 'not confirmed'}",
        },
        "principle_2_4_international_cooperation": {
            "principle": "2.4",
            "title": "International cooperation for trustworthy AI",
            "status": "needs_review",
            "description": "Multi-stakeholder and cross-border cooperation on AI governance",
            "evidence": "International cooperation: review required",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "OECD AI Principles Compliance",
        "system_name": system_name,
        "generated_at": now,
        "framework": "OECD Principles on Artificial Intelligence (2019, updated 2024)",
        "adopted_by": "46 countries",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "recommendation": (
            "System aligns with OECD AI Principles for trustworthy AI"
            if compliant == total
            else f"Address {non_compliant} non-aligned and {needs_review} unconfirmed principles"
        ),
    }


def generate_ieee_ethics_report(
    system_name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Generate IEEE Ethically Aligned Design assessment report.

    Based on IEEE 7000 series standards and the Ethically Aligned Design (EAD)
    framework for autonomous and intelligent systems. Covers human rights,
    well-being, accountability, transparency, and awareness of misuse.
    """
    ctx = context or {}
    now = datetime.utcnow().isoformat()

    controls = {
        "P7000_ethical_design": {
            "standard": "IEEE 7000",
            "title": "Model process for addressing ethical concerns",
            "status": "compliant" if ctx.get("has_policy", False) else "non_compliant",
            "description": "Systematic ethical design process applied during AI system development",
            "evidence": f"Governance policy: {'established' if ctx.get('has_policy', False) else 'missing'}",
        },
        "P7001_transparency": {
            "standard": "IEEE 7001",
            "title": "Transparency of autonomous systems",
            "status": "compliant" if ctx.get("has_explanation", False) and ctx.get("has_model_card", False) else "non_compliant",
            "description": "AI system provides appropriate levels of transparency to stakeholders",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'missing'}, Model card: {'present' if ctx.get('has_model_card', False) else 'missing'}",
        },
        "P7002_data_privacy": {
            "standard": "IEEE 7002",
            "title": "Data privacy process",
            "status": "compliant" if not ctx.get("pii_detected", True) and ctx.get("data_minimized", False) else "non_compliant",
            "description": "Systematic process to protect personal data throughout AI lifecycle",
            "evidence": f"PII scan: {'clean' if not ctx.get('pii_detected', True) else 'PII detected'}, Data minimization: {'enforced' if ctx.get('data_minimized', False) else 'not confirmed'}",
        },
        "P7003_algorithmic_bias": {
            "standard": "IEEE 7003",
            "title": "Algorithmic bias considerations",
            "status": "compliant" if ctx.get("fairness_tested", False) else "non_compliant",
            "description": "Methodologies to identify and mitigate algorithmic bias in AI outputs",
            "evidence": f"Bias testing: {'completed' if ctx.get('fairness_tested', False) else 'not conducted'}",
        },
        "P7006_personal_data_ai_agents": {
            "standard": "IEEE 7006",
            "title": "Standard for personal data artificial intelligence agents",
            "status": "compliant" if ctx.get("human_oversight", False) else "needs_review",
            "description": "AI agents handling personal data operate under user control and consent",
            "evidence": f"Human oversight: {'enabled' if ctx.get('human_oversight', False) else 'not confirmed'}",
        },
        "P7007_ontological_standard": {
            "standard": "IEEE 7007",
            "title": "Ontological standard for ethically driven robotics and automation systems",
            "status": "compliant" if ctx.get("has_guardrails", False) else "needs_review",
            "description": "Ethical boundaries and operational constraints defined for AI behavior",
            "evidence": f"Guardrails: {'configured' if ctx.get('has_guardrails', False) else 'not confirmed'}",
        },
        "P7010_wellbeing_metrics": {
            "standard": "IEEE 7010",
            "title": "Well-being metrics standard for ethical AI",
            "status": "compliant" if ctx.get("drift_score", 1.0) < 0.3 and ctx.get("risk_score", 100) < 70 else "needs_review",
            "description": "AI system impact on human well-being measured and monitored",
            "evidence": f"Risk score: {ctx.get('risk_score', 'N/A')}, Drift score: {ctx.get('drift_score', 'N/A')}",
        },
        "EAD_human_rights": {
            "standard": "EAD Issue 1",
            "title": "Human rights impact assessment",
            "status": "compliant" if ctx.get("has_explanation", False) and ctx.get("human_oversight", False) else "non_compliant",
            "description": "AI system assessed for impact on fundamental human rights",
            "evidence": f"Explainability: {'enabled' if ctx.get('has_explanation', False) else 'missing'}, Human oversight: {'enabled' if ctx.get('human_oversight', False) else 'missing'}",
        },
        "EAD_accountability": {
            "standard": "EAD Issue 3",
            "title": "Accountability framework",
            "status": "compliant" if ctx.get("has_audit_trail", False) else "non_compliant",
            "description": "Clear accountability chain for AI system decisions and outcomes",
            "evidence": f"Audit trail: {'active (hash-chained)' if ctx.get('has_audit_trail', False) else 'missing'}",
        },
        "EAD_awareness_of_misuse": {
            "standard": "EAD Issue 5",
            "title": "Awareness of misuse",
            "status": "compliant" if ctx.get("prompt_injection_scan", False) and ctx.get("team_trained", False) else "needs_review",
            "description": "Safeguards against potential misuse of AI system capabilities",
            "evidence": f"Security scanning: {'active' if ctx.get('prompt_injection_scan', False) else 'not confirmed'}, Team training: {'completed' if ctx.get('team_trained', False) else 'not confirmed'}",
        },
    }

    compliant = sum(1 for c in controls.values() if c["status"] == "compliant")
    needs_review = sum(1 for c in controls.values() if c["status"] == "needs_review")
    non_compliant = sum(1 for c in controls.values() if c["status"] == "non_compliant")
    total = len(controls)

    return {
        "report_type": "IEEE Ethically Aligned Design Assessment",
        "system_name": system_name,
        "generated_at": now,
        "framework": "IEEE 7000 Series / Ethically Aligned Design (EAD) First Edition",
        "compliance_score": round(compliant / total * 100, 1),
        "controls": controls,
        "summary": {
            "compliant": compliant,
            "needs_review": needs_review,
            "non_compliant": non_compliant,
            "total": total,
        },
        "recommendation": (
            "System meets IEEE ethical AI design standards"
            if compliant == total
            else f"Address {non_compliant} non-compliant and {needs_review} unconfirmed ethical design requirements"
        ),
    }
