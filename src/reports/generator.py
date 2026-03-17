"""Regulatory Report Generator — EU AI Act, NIST AI RMF, ISO 42001."""

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
