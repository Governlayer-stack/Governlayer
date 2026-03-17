"""Governance Knowledge Graph — maps regulations, risks, controls, and their relationships."""

from datetime import datetime
from typing import Any, Dict, List, Optional


# Complete knowledge graph: regulation -> requirements -> controls -> risks
KNOWLEDGE_GRAPH = {
    "regulations": {
        "eu_ai_act": {
            "name": "EU AI Act",
            "jurisdiction": "European Union",
            "effective_date": "2026-08-01",
            "requirements": ["risk_classification", "transparency", "human_oversight", "data_governance", "technical_documentation", "accuracy_robustness"],
            "risk_tiers": ["unacceptable", "high", "limited", "minimal"],
            "penalties": {"max_fine_pct": 7, "max_fine_eur": 35000000},
        },
        "nist_ai_rmf": {
            "name": "NIST AI RMF 1.0",
            "jurisdiction": "United States",
            "effective_date": "2023-01-26",
            "requirements": ["govern", "map", "measure", "manage"],
            "voluntary": True,
        },
        "iso_42001": {
            "name": "ISO/IEC 42001:2023",
            "jurisdiction": "International",
            "effective_date": "2023-12-18",
            "requirements": ["context", "leadership", "planning", "support", "operation", "performance", "improvement"],
            "certification_available": True,
        },
        "hitrust_ai": {
            "name": "HITRUST AI Assurance",
            "jurisdiction": "United States",
            "effective_date": "2024-06-01",
            "requirements": ["data_protection", "access_control", "audit_logging", "incident_response", "vendor_management"],
            "industries": ["healthcare", "pharma", "insurance"],
        },
        "nyc_ll144": {
            "name": "NYC Local Law 144",
            "jurisdiction": "New York City",
            "effective_date": "2023-07-05",
            "requirements": ["bias_audit", "public_notice", "annual_audit", "candidate_notification"],
            "industries": ["employment", "hr_tech"],
            "penalties": {"max_fine_per_violation": 1500},
        },
        "colorado_sb169": {
            "name": "Colorado SB 21-169",
            "jurisdiction": "Colorado",
            "effective_date": "2024-02-01",
            "requirements": ["impact_assessment", "bias_testing", "consumer_disclosure", "opt_out_mechanism"],
            "industries": ["insurance"],
        },
        "soc2": {
            "name": "SOC 2 Type II",
            "jurisdiction": "United States",
            "effective_date": "2010-01-01",
            "requirements": ["security", "availability", "processing_integrity", "confidentiality", "privacy"],
            "certification_available": True,
        },
        "gdpr": {
            "name": "GDPR",
            "jurisdiction": "European Union",
            "effective_date": "2018-05-25",
            "requirements": ["lawful_processing", "data_minimization", "purpose_limitation", "accuracy", "storage_limitation", "integrity_confidentiality", "accountability"],
            "penalties": {"max_fine_pct": 4, "max_fine_eur": 20000000},
        },
    },
    "controls": {
        "risk_assessment": {
            "name": "AI Risk Assessment",
            "description": "Systematic evaluation of AI system risks",
            "maps_to": ["eu_ai_act", "nist_ai_rmf", "iso_42001", "hitrust_ai"],
            "governlayer_feature": "POST /v1/risk",
        },
        "bias_testing": {
            "name": "Bias & Fairness Testing",
            "description": "Statistical testing for discriminatory outcomes",
            "maps_to": ["eu_ai_act", "nyc_ll144", "colorado_sb169", "nist_ai_rmf"],
            "governlayer_feature": "POST /v1/analytics/fairness",
        },
        "drift_monitoring": {
            "name": "Behavioral Drift Monitoring",
            "description": "Continuous monitoring for model behavior changes",
            "maps_to": ["eu_ai_act", "nist_ai_rmf", "iso_42001"],
            "governlayer_feature": "POST /v1/drift",
        },
        "audit_trail": {
            "name": "Immutable Audit Trail",
            "description": "Hash-chained record of all governance decisions",
            "maps_to": ["soc2", "gdpr", "hitrust_ai", "iso_42001", "eu_ai_act"],
            "governlayer_feature": "GET /ledger",
        },
        "explainability": {
            "name": "Model Explainability",
            "description": "Feature attribution and counterfactual explanations",
            "maps_to": ["eu_ai_act", "gdpr", "nist_ai_rmf"],
            "governlayer_feature": "POST /v1/analytics/explain",
        },
        "data_governance": {
            "name": "Data Governance & PII Protection",
            "description": "PII detection, redaction, and data handling controls",
            "maps_to": ["gdpr", "eu_ai_act", "hitrust_ai", "soc2"],
            "governlayer_feature": "POST /v1/analytics/security-scan",
        },
        "model_registry": {
            "name": "AI Model/Agent Registry",
            "description": "Centralized inventory of all AI systems",
            "maps_to": ["eu_ai_act", "nist_ai_rmf", "iso_42001"],
            "governlayer_feature": "POST /v1/models, POST /v1/agents",
        },
        "incident_management": {
            "name": "Incident Management",
            "description": "Lifecycle tracking of AI governance incidents",
            "maps_to": ["soc2", "hitrust_ai", "iso_42001", "nist_ai_rmf"],
            "governlayer_feature": "POST /v1/incidents",
        },
        "policy_enforcement": {
            "name": "Policy-as-Code Enforcement",
            "description": "Real-time policy evaluation with allow/block decisions",
            "maps_to": ["eu_ai_act", "nist_ai_rmf", "iso_42001", "soc2"],
            "governlayer_feature": "POST /v1/policies/evaluate",
        },
        "human_oversight": {
            "name": "Human-in-the-Loop Oversight",
            "description": "Escalation workflows for high-risk decisions",
            "maps_to": ["eu_ai_act", "nist_ai_rmf"],
            "governlayer_feature": "Agent orchestrator escalation",
        },
        "security_scanning": {
            "name": "Prompt Injection & Security Scanning",
            "description": "Detection of adversarial inputs and security threats",
            "maps_to": ["soc2", "hitrust_ai", "nist_ai_rmf"],
            "governlayer_feature": "POST /v1/analytics/security-scan",
        },
        "compliance_reporting": {
            "name": "Regulatory Compliance Reports",
            "description": "Auto-generated compliance documentation",
            "maps_to": ["eu_ai_act", "nist_ai_rmf", "iso_42001", "soc2", "hitrust_ai"],
            "governlayer_feature": "POST /v1/reports",
        },
    },
    "risk_categories": {
        "bias_discrimination": {
            "name": "Bias & Discrimination",
            "regulations": ["eu_ai_act", "nyc_ll144", "colorado_sb169"],
            "controls": ["bias_testing", "explainability", "human_oversight"],
            "severity": "critical",
        },
        "privacy_data": {
            "name": "Privacy & Data Protection",
            "regulations": ["gdpr", "hitrust_ai", "soc2"],
            "controls": ["data_governance", "audit_trail", "security_scanning"],
            "severity": "critical",
        },
        "security_adversarial": {
            "name": "Security & Adversarial Attacks",
            "regulations": ["soc2", "hitrust_ai", "nist_ai_rmf"],
            "controls": ["security_scanning", "drift_monitoring", "incident_management"],
            "severity": "high",
        },
        "transparency_accountability": {
            "name": "Transparency & Accountability",
            "regulations": ["eu_ai_act", "nist_ai_rmf", "gdpr"],
            "controls": ["explainability", "model_registry", "audit_trail", "compliance_reporting"],
            "severity": "high",
        },
        "performance_reliability": {
            "name": "Performance & Reliability",
            "regulations": ["eu_ai_act", "iso_42001", "nist_ai_rmf"],
            "controls": ["drift_monitoring", "risk_assessment", "incident_management"],
            "severity": "medium",
        },
        "governance_oversight": {
            "name": "Governance & Oversight",
            "regulations": ["iso_42001", "nist_ai_rmf", "eu_ai_act"],
            "controls": ["policy_enforcement", "human_oversight", "compliance_reporting"],
            "severity": "medium",
        },
    },
}


def query_knowledge_graph(
    regulation: Optional[str] = None,
    control: Optional[str] = None,
    risk_category: Optional[str] = None,
) -> Dict:
    """Query the governance knowledge graph for relationships."""
    result = {}

    if regulation:
        reg = KNOWLEDGE_GRAPH["regulations"].get(regulation)
        if reg:
            related_controls = [
                {"id": cid, **cdata}
                for cid, cdata in KNOWLEDGE_GRAPH["controls"].items()
                if regulation in cdata.get("maps_to", [])
            ]
            related_risks = [
                {"id": rid, **rdata}
                for rid, rdata in KNOWLEDGE_GRAPH["risk_categories"].items()
                if regulation in rdata.get("regulations", [])
            ]
            result = {
                "regulation": {**reg, "id": regulation},
                "controls": related_controls,
                "risk_categories": related_risks,
                "total_controls": len(related_controls),
                "total_risks": len(related_risks),
            }

    elif control:
        ctrl = KNOWLEDGE_GRAPH["controls"].get(control)
        if ctrl:
            related_regs = [
                {"id": rid, **KNOWLEDGE_GRAPH["regulations"][rid]}
                for rid in ctrl.get("maps_to", [])
                if rid in KNOWLEDGE_GRAPH["regulations"]
            ]
            result = {
                "control": {**ctrl, "id": control},
                "regulations": related_regs,
                "total_regulations": len(related_regs),
            }

    elif risk_category:
        risk = KNOWLEDGE_GRAPH["risk_categories"].get(risk_category)
        if risk:
            related_regs = [
                {"id": rid, **KNOWLEDGE_GRAPH["regulations"][rid]}
                for rid in risk.get("regulations", [])
                if rid in KNOWLEDGE_GRAPH["regulations"]
            ]
            related_controls = [
                {"id": cid, **KNOWLEDGE_GRAPH["controls"][cid]}
                for cid in risk.get("controls", [])
                if cid in KNOWLEDGE_GRAPH["controls"]
            ]
            result = {
                "risk_category": {**risk, "id": risk_category},
                "regulations": related_regs,
                "controls": related_controls,
            }

    else:
        result = {
            "regulations": list(KNOWLEDGE_GRAPH["regulations"].keys()),
            "controls": list(KNOWLEDGE_GRAPH["controls"].keys()),
            "risk_categories": list(KNOWLEDGE_GRAPH["risk_categories"].keys()),
            "total_regulations": len(KNOWLEDGE_GRAPH["regulations"]),
            "total_controls": len(KNOWLEDGE_GRAPH["controls"]),
            "total_risk_categories": len(KNOWLEDGE_GRAPH["risk_categories"]),
        }

    return result


def get_compliance_gap_analysis(active_controls: List[str]) -> Dict:
    """Analyze which regulations have gaps based on active controls."""
    gaps = {}
    for reg_id, reg in KNOWLEDGE_GRAPH["regulations"].items():
        required_controls = [
            cid for cid, cdata in KNOWLEDGE_GRAPH["controls"].items()
            if reg_id in cdata.get("maps_to", [])
        ]
        active = [c for c in required_controls if c in active_controls]
        missing = [c for c in required_controls if c not in active_controls]

        coverage = len(active) / len(required_controls) * 100 if required_controls else 100
        gaps[reg_id] = {
            "regulation": reg["name"],
            "required_controls": len(required_controls),
            "active_controls": len(active),
            "missing_controls": missing,
            "coverage_pct": round(coverage, 1),
            "compliant": len(missing) == 0,
        }

    return {
        "total_regulations": len(gaps),
        "fully_compliant": sum(1 for g in gaps.values() if g["compliant"]),
        "gaps": gaps,
    }


def get_advisory_recommendations(context: Dict[str, Any]) -> Dict:
    """Generate governance advisory recommendations based on context."""
    recommendations = []
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    risk_score = context.get("risk_score", 0)
    has_fairness = context.get("fairness_tested", False)
    has_model_card = context.get("has_model_card", False)
    has_policy = context.get("has_policy", False)
    has_incidents = context.get("open_incidents", 0) > 0
    model_count = context.get("model_count", 0)
    agent_count = context.get("agent_count", 0)
    drift_score = context.get("drift_score", 0)

    if risk_score > 70:
        recommendations.append({
            "priority": "critical",
            "category": "Risk Management",
            "title": "High risk score detected",
            "action": "Review and mitigate risk factors. Consider restricting model to staging until risk is below 70.",
            "endpoint": "POST /v1/risk",
            "regulation": "EU AI Act Art. 9, NIST AI RMF Measure",
        })

    if not has_fairness:
        recommendations.append({
            "priority": "high",
            "category": "Bias & Fairness",
            "title": "No fairness testing conducted",
            "action": "Run bias testing on all production models. Required for NYC LL144 and EU AI Act compliance.",
            "endpoint": "POST /v1/analytics/fairness",
            "regulation": "NYC LL144, Colorado SB 21-169, EU AI Act Art. 10",
        })

    if not has_model_card:
        recommendations.append({
            "priority": "high",
            "category": "Transparency",
            "title": "Model cards missing",
            "action": "Create model cards documenting intended use, limitations, and ethical considerations.",
            "endpoint": "POST /v1/models/{id}/card",
            "regulation": "EU AI Act Art. 11, 13",
        })

    if not has_policy:
        recommendations.append({
            "priority": "high",
            "category": "Governance",
            "title": "No governance policies configured",
            "action": "Create and activate governance policies with enforcement rules.",
            "endpoint": "POST /v1/policies",
            "regulation": "NIST AI RMF Govern, ISO 42001 Clause 5",
        })

    if drift_score > 0.3:
        recommendations.append({
            "priority": "high",
            "category": "Performance",
            "title": "Behavioral drift exceeds threshold",
            "action": "Investigate drift causes. Consider retraining or rolling back the model.",
            "endpoint": "POST /v1/drift",
            "regulation": "EU AI Act Art. 15, ISO 42001 Clause 9",
        })

    if model_count > 0 and agent_count == 0:
        recommendations.append({
            "priority": "medium",
            "category": "Agent Governance",
            "title": "Models registered but no agents tracked",
            "action": "Register AI agents that use your models to track the full AI supply chain.",
            "endpoint": "POST /v1/agents",
            "regulation": "NIST AI RMF Map",
        })

    if has_incidents:
        recommendations.append({
            "priority": "medium",
            "category": "Incident Management",
            "title": "Open incidents require attention",
            "action": "Review and remediate open incidents. Document root causes and resolutions.",
            "endpoint": "GET /v1/incidents",
            "regulation": "SOC 2, HITRUST, ISO 42001 Clause 10",
        })

    if not recommendations:
        recommendations.append({
            "priority": "low",
            "category": "Continuous Improvement",
            "title": "Governance posture is strong",
            "action": "Schedule periodic compliance report generation and share with stakeholders.",
            "endpoint": "POST /v1/reports",
            "regulation": "All frameworks",
        })

    recommendations.sort(key=lambda x: priority_order.get(x["priority"], 99))

    return {
        "total_recommendations": len(recommendations),
        "critical": sum(1 for r in recommendations if r["priority"] == "critical"),
        "high": sum(1 for r in recommendations if r["priority"] == "high"),
        "recommendations": recommendations,
    }
