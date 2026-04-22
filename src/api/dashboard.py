"""Organization Dashboard Healthcheck — single endpoint for full environment overview."""

from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from src.security.api_key_auth import AuthContext, verify_api_key_or_jwt
from src.models.database import get_db
from src.models.registry import RegisteredModel, Incident, IncidentStatus, IncidentSeverity, ModelLifecycle
from src.models.policy import GovernancePolicy
from src.models.agents import AIAgent

router = APIRouter(tags=["Dashboard"])


@router.get("/v1/dashboard")
def org_dashboard_healthcheck(auth: AuthContext = Depends(verify_api_key_or_jwt), db: Session = Depends(get_db)):
    """One-click organization healthcheck — everything at a glance.

    Returns models, incidents, compliance, policies, agents, and system status
    so clients can understand their entire environment in one API call.
    Scoped to the authenticated organization when using API key auth.
    """
    # --- Models ---
    query = db.query(RegisteredModel)
    if auth.org_id:
        query = query.filter(RegisteredModel.org_id == auth.org_id)
    models = query.all()
    model_count = len(models)
    lifecycle_breakdown = {}
    governance_breakdown = {}
    avg_risk = 0.0
    risk_scores = []

    for m in models:
        lc = m.lifecycle.value if m.lifecycle else "unknown"
        lifecycle_breakdown[lc] = lifecycle_breakdown.get(lc, 0) + 1
        gs = m.governance_status or "unknown"
        governance_breakdown[gs] = governance_breakdown.get(gs, 0) + 1
        if m.risk_score is not None:
            risk_scores.append(m.risk_score)

    if risk_scores:
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1)

    # --- Incidents ---
    query = db.query(Incident)
    if auth.org_id:
        query = query.filter(Incident.org_id == auth.org_id)
    incidents = query.all()
    open_incidents = sum(1 for i in incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING))
    critical_incidents = sum(
        1 for i in incidents
        if i.severity == IncidentSeverity.CRITICAL
        and i.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)
    )
    incident_by_severity = {}
    for i in incidents:
        sev = i.severity.value if i.severity else "unknown"
        incident_by_severity[sev] = incident_by_severity.get(sev, 0) + 1

    recent_incidents = sorted(incidents, key=lambda x: x.created_at or datetime.min, reverse=True)[:5]

    # --- Policies ---
    query = db.query(GovernancePolicy).filter(GovernancePolicy.is_active == True)
    if auth.org_id:
        query = query.filter(GovernancePolicy.org_id == auth.org_id)
    policies = query.all()
    total_rules = sum(len(p.rules) if p.rules else 0 for p in policies)

    # --- Agents ---
    query = db.query(AIAgent)
    if auth.org_id:
        query = query.filter(AIAgent.org_id == auth.org_id)
    agents = query.all()
    agent_count = len(agents)
    agent_status_breakdown = {}
    shadow_count = 0
    for a in agents:
        status_val = a.status.value if a.status else "unknown"
        agent_status_breakdown[status_val] = agent_status_breakdown.get(status_val, 0) + 1
        if a.is_shadow:
            shadow_count += 1

    # --- Overall Health ---
    health_score = 100
    health_issues = []

    if critical_incidents > 0:
        health_score -= 30
        health_issues.append(f"{critical_incidents} critical incident(s) open")
    if open_incidents > 3:
        health_score -= 15
        health_issues.append(f"{open_incidents} open incidents")
    if avg_risk > 70:
        health_score -= 20
        health_issues.append(f"Average risk score {avg_risk} exceeds threshold")

    non_compliant = governance_breakdown.get("non_compliant", 0)
    if non_compliant > 0:
        health_score -= 15
        health_issues.append(f"{non_compliant} model(s) non-compliant")

    if len(policies) == 0:
        health_score -= 10
        health_issues.append("No active governance policies")

    production_models = lifecycle_breakdown.get("production", 0)
    ungoverned = governance_breakdown.get("pending", 0)
    if production_models > 0 and ungoverned > 0:
        health_score -= 10
        health_issues.append(f"{ungoverned} model(s) pending governance review")

    if shadow_count > 0:
        health_score -= 10
        health_issues.append(f"{shadow_count} shadow AI agent(s) detected")

    health_score = max(0, health_score)

    if health_score >= 90:
        health_status = "healthy"
    elif health_score >= 70:
        health_status = "warning"
    elif health_score >= 50:
        health_status = "degraded"
    else:
        health_status = "critical"

    return {
        "dashboard": {
            "org_id": auth.org_id,
            "generated_at": datetime.utcnow().isoformat(),
            "health": {
                "score": health_score,
                "status": health_status,
                "issues": health_issues,
            },
            "models": {
                "total": model_count,
                "by_lifecycle": lifecycle_breakdown,
                "by_governance_status": governance_breakdown,
                "average_risk_score": avg_risk,
                "production_count": production_models,
            },
            "incidents": {
                "total": len(incidents),
                "open": open_incidents,
                "critical_open": critical_incidents,
                "by_severity": incident_by_severity,
                "recent": [
                    {
                        "id": i.id,
                        "title": i.title,
                        "severity": i.severity.value if i.severity else None,
                        "status": i.status.value if i.status else None,
                        "created_at": i.created_at.isoformat() if i.created_at else None,
                    }
                    for i in recent_incidents
                ],
            },
            "policies": {
                "active_policies": len(policies),
                "total_rules": total_rules,
                "policies": [
                    {"id": p.id, "name": p.name, "rules": len(p.rules) if p.rules else 0}
                    for p in policies
                ],
            },
            "agents": {
                "total": agent_count,
                "by_status": agent_status_breakdown,
                "shadow_detected": shadow_count,
            },
            "quick_actions": [
                {"action": "Register a model", "endpoint": "POST /v1/models", "priority": "high" if model_count == 0 else "low"},
                {"action": "Run governance scan", "endpoint": "POST /v1/scan", "priority": "medium"},
                {"action": "Create policy", "endpoint": "POST /v1/policies", "priority": "high" if len(policies) == 0 else "low"},
                {"action": "Generate compliance report", "endpoint": "POST /v1/reports", "priority": "medium"},
                {"action": "Test model fairness", "endpoint": "POST /v1/analytics/fairness", "priority": "medium"},
                {"action": "Security scan", "endpoint": "POST /v1/analytics/security-scan", "priority": "high"},
            ],
        },
    }


@router.get("/dashboard")
def serve_dashboard(request: Request):
    """Serve the governance dashboard UI."""
    import os
    paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs", "dashboard", "index.html"),
        os.path.join("/app", "docs", "dashboard", "index.html"),
    ]
    for path in paths:
        if os.path.exists(path):
            with open(path) as f:
                return HTMLResponse(f.read())
    return {"error": "Dashboard not found", "hint": "Dashboard UI is available at /v1/dashboard (JSON API)"}
