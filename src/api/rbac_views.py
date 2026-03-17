"""RBAC Dashboard Views — role-based dashboards for different team functions."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter

from src.models.database import SessionLocal
from src.models.registry import RegisteredModel, Incident, IncidentStatus, IncidentSeverity
from src.models.policy import GovernancePolicy

router = APIRouter(prefix="/v1/views", tags=["RBAC Views"])


def _get_base_stats(db):
    """Shared stats used across all views."""
    models = db.query(RegisteredModel).all()
    incidents = db.query(Incident).all()
    policies = db.query(GovernancePolicy).filter(GovernancePolicy.is_active == True).all()
    return models, incidents, policies


@router.get("/engineering")
def engineering_view():
    """Engineering team dashboard — models, drift, performance, technical health."""
    db = SessionLocal()
    try:
        models, incidents, policies = _get_base_stats(db)

        risk_scores = [m.risk_score for m in models if m.risk_score is not None]
        lifecycle = {}
        for m in models:
            lc = m.lifecycle.value if m.lifecycle else "unknown"
            lifecycle[lc] = lifecycle.get(lc, 0) + 1

        tech_incidents = [i for i in incidents if i.category in ("drift", "performance", "security")]

        return {
            "view": "engineering",
            "generated_at": datetime.utcnow().isoformat(),
            "models": {
                "total": len(models),
                "by_lifecycle": lifecycle,
                "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else None,
                "high_risk": sum(1 for s in risk_scores if s > 70),
            },
            "technical_incidents": {
                "total": len(tech_incidents),
                "open": sum(1 for i in tech_incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)),
            },
            "actions": [
                {"action": "Run drift detection", "endpoint": "POST /v1/drift"},
                {"action": "Check data drift", "endpoint": "POST /v1/analytics/data-drift"},
                {"action": "Security scan", "endpoint": "POST /v1/analytics/security-scan"},
                {"action": "View model registry", "endpoint": "GET /v1/models"},
            ],
        }
    finally:
        db.close()


@router.get("/compliance")
def compliance_view():
    """Compliance/Legal team dashboard — regulatory status, policy adherence, audit readiness."""
    db = SessionLocal()
    try:
        models, incidents, policies = _get_base_stats(db)

        governance_status = {}
        for m in models:
            gs = m.governance_status or "unknown"
            governance_status[gs] = governance_status.get(gs, 0) + 1

        compliance_incidents = [i for i in incidents if i.category in ("compliance", "bias")]

        return {
            "view": "compliance",
            "generated_at": datetime.utcnow().isoformat(),
            "governance_posture": {
                "models_governed": len(models),
                "by_status": governance_status,
                "compliant_pct": round(governance_status.get("compliant", 0) / len(models) * 100, 1) if models else 0,
            },
            "policies": {
                "active": len(policies),
                "total_rules": sum(len(p.rules) if p.rules else 0 for p in policies),
            },
            "compliance_incidents": {
                "total": len(compliance_incidents),
                "open": sum(1 for i in compliance_incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)),
            },
            "supported_frameworks": [
                "EU AI Act", "NIST AI RMF", "ISO 42001", "HITRUST",
                "NYC LL144", "Colorado SB 21-169", "SOC 2", "GDPR",
            ],
            "actions": [
                {"action": "Generate compliance report", "endpoint": "POST /v1/reports"},
                {"action": "Run fairness audit", "endpoint": "POST /v1/analytics/fairness"},
                {"action": "Gap analysis", "endpoint": "POST /v1/knowledge/gap-analysis"},
                {"action": "View policies", "endpoint": "GET /v1/policies"},
            ],
        }
    finally:
        db.close()


@router.get("/executive")
def executive_view():
    """Executive/C-suite dashboard — high-level health, risk posture, business impact."""
    db = SessionLocal()
    try:
        models, incidents, policies = _get_base_stats(db)

        risk_scores = [m.risk_score for m in models if m.risk_score is not None]
        critical_incidents = sum(
            1 for i in incidents
            if i.severity == IncidentSeverity.CRITICAL
            and i.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)
        )
        open_incidents = sum(1 for i in incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING))

        health = 100
        if critical_incidents > 0:
            health -= 30
        if open_incidents > 5:
            health -= 15
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
        if avg_risk > 70:
            health -= 20
        health = max(0, health)

        return {
            "view": "executive",
            "generated_at": datetime.utcnow().isoformat(),
            "health_score": health,
            "health_status": "healthy" if health >= 90 else "warning" if health >= 70 else "degraded" if health >= 50 else "critical",
            "kpis": {
                "models_governed": len(models),
                "avg_risk_score": avg_risk,
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "active_policies": len(policies),
                "frameworks_supported": 8,
            },
            "risk_summary": "AI governance posture is strong" if health >= 90 else "Attention needed on open incidents and risk scores",
        }
    finally:
        db.close()


@router.get("/security")
def security_view():
    """Security team dashboard — threats, vulnerabilities, prompt injection, PII exposure."""
    db = SessionLocal()
    try:
        models, incidents, policies = _get_base_stats(db)

        security_incidents = [i for i in incidents if i.category in ("security", "injection", "pii")]

        return {
            "view": "security",
            "generated_at": datetime.utcnow().isoformat(),
            "security_incidents": {
                "total": len(security_incidents),
                "open": sum(1 for i in security_incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)),
                "critical": sum(1 for i in security_incidents if i.severity == IncidentSeverity.CRITICAL),
            },
            "capabilities": {
                "prompt_injection_defense": True,
                "pii_detection": True,
                "pii_redaction": True,
                "security_scanning": True,
                "shadow_ai_detection": True,
                "hash_chained_audit": True,
            },
            "actions": [
                {"action": "Run security scan", "endpoint": "POST /v1/analytics/security-scan"},
                {"action": "Scan for shadow AI", "endpoint": "POST /v1/agents/discovery/scan"},
                {"action": "View shadow detections", "endpoint": "GET /v1/agents/discovery/detections"},
                {"action": "Review security incidents", "endpoint": "GET /v1/incidents?category=security"},
            ],
        }
    finally:
        db.close()


@router.get("/data-science")
def data_science_view():
    """Data Science team dashboard — model performance, fairness, explainability, drift."""
    db = SessionLocal()
    try:
        models, incidents, policies = _get_base_stats(db)

        production_models = [m for m in models if m.lifecycle and m.lifecycle.value == "production"]
        risk_scores = [m.risk_score for m in models if m.risk_score is not None]

        return {
            "view": "data_science",
            "generated_at": datetime.utcnow().isoformat(),
            "models": {
                "total": len(models),
                "in_production": len(production_models),
                "avg_risk": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else None,
            },
            "capabilities": {
                "fairness_testing": {"endpoint": "POST /v1/analytics/fairness", "metrics": ["disparate_impact", "demographic_parity", "equalized_odds"]},
                "explainability": {"endpoint": "POST /v1/analytics/explain", "methods": ["feature_attribution", "counterfactuals"]},
                "data_drift": {"endpoint": "POST /v1/analytics/data-drift", "methods": ["PSI", "KS_test"]},
                "behavioral_drift": {"endpoint": "POST /v1/drift", "method": "embedding_similarity"},
            },
            "actions": [
                {"action": "Test model fairness", "endpoint": "POST /v1/analytics/fairness"},
                {"action": "Generate explanation", "endpoint": "POST /v1/analytics/explain"},
                {"action": "Check data drift", "endpoint": "POST /v1/analytics/data-drift"},
                {"action": "Register new model", "endpoint": "POST /v1/models"},
                {"action": "Create model card", "endpoint": "POST /v1/models/{id}/card"},
            ],
        }
    finally:
        db.close()
