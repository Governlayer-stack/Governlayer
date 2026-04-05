"""Incident Management API — full lifecycle tracking."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.models.database import get_db, log_mutation
from src.models.registry import Incident, IncidentSeverity, IncidentStatus
from src.security.api_key_auth import AuthContext, require_scope, verify_api_key_or_jwt
from src.security.auth import verify_token

router = APIRouter(prefix="/v1/incidents", tags=["Incidents"])


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    model_id: Optional[int] = None
    severity: str = "medium"
    category: Optional[str] = None
    reporter: Optional[str] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assignee: Optional[str] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    impact: Optional[str] = None


@router.post("")
def create_incident(data: IncidentCreate,
                    auth: AuthContext = Depends(require_scope("govern")),
                    db: Session = Depends(get_db)):
    """Report a new AI governance incident."""
    incident = Incident(
        title=data.title,
        description=data.description,
        model_id=data.model_id,
        severity=IncidentSeverity(data.severity),
        category=data.category,
        reporter=data.reporter or auth.identity,
        timeline=[{"timestamp": datetime.utcnow().isoformat(), "action": "created", "actor": auth.identity}],
    )
    db.add(incident)
    log_mutation(db, auth.identity, "create", "incident", details=f"Incident: {data.title}")
    db.commit()
    db.refresh(incident)

    # Fire webhook for incident creation
    from src.api.webhooks import dispatch_event
    dispatch_event("incident.created", {
        "id": incident.id, "title": data.title,
        "severity": data.severity, "category": data.category,
    }, auth.org_id, db)

    # Email notification for high/critical incidents
    if data.severity in ("high", "critical"):
        from src.notifications.email import send_email
        from src.notifications.templates import incident_alert_email
        subject, html = incident_alert_email(data.title, data.severity, incident.id)
        send_email(auth.identity, subject, html)

    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "created_at": incident.created_at.isoformat(),
    }


@router.get("")
def list_incidents(status: Optional[str] = None, severity: Optional[str] = None,
                   page: int = 1, limit: int = 50, current_user: str = Depends(verify_token),
                   db: Session = Depends(get_db)):
    """List all incidents with optional filters and pagination."""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity.value if i.severity else None,
                "status": i.status.value if i.status else None,
                "category": i.category,
                "model_id": i.model_id,
                "reporter": i.reporter,
                "assignee": i.assignee,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in incidents
        ],
    }


@router.get("/{incident_id}")
def get_incident(incident_id: int, current_user: str = Depends(verify_token),
                 db: Session = Depends(get_db)):
    """Get detailed incident information."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value if incident.severity else None,
        "status": incident.status.value if incident.status else None,
        "category": incident.category,
        "model_id": incident.model_id,
        "root_cause": incident.root_cause,
        "resolution": incident.resolution,
        "impact": incident.impact,
        "reporter": incident.reporter,
        "assignee": incident.assignee,
        "timeline": incident.timeline,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


@router.patch("/{incident_id}")
def update_incident(incident_id: int, data: IncidentUpdate,
                    auth: AuthContext = Depends(require_scope("govern")),
                    db: Session = Depends(get_db)):
    """Update incident status, assignment, or resolution."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes = []
    timeline_entry = {"timestamp": datetime.utcnow().isoformat(), "actor": auth.identity}

    if data.status:
        valid = [e.value for e in IncidentStatus]
        if data.status not in valid:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")
        incident.status = IncidentStatus(data.status)
        timeline_entry["action"] = f"status changed to {data.status}"
        changes.append(f"status->{data.status}")
        if data.status in ("resolved", "closed"):
            incident.resolved_at = datetime.utcnow()

    if data.severity:
        incident.severity = IncidentSeverity(data.severity)
        timeline_entry["action"] = f"severity changed to {data.severity}"
        changes.append(f"severity->{data.severity}")

    if data.assignee:
        incident.assignee = data.assignee
        timeline_entry["action"] = f"assigned to {data.assignee}"
        changes.append(f"assignee->{data.assignee}")

    if data.root_cause:
        incident.root_cause = data.root_cause
    if data.resolution:
        incident.resolution = data.resolution
    if data.impact:
        incident.impact = data.impact

    incident.timeline = (incident.timeline or []) + [timeline_entry]
    incident.updated_at = datetime.utcnow()
    log_mutation(db, auth.identity, "update", "incident", incident_id,
                 "; ".join(changes) if changes else "updated fields")
    db.commit()

    # Fire webhook for incident updates
    if changes:
        from src.api.webhooks import dispatch_event
        event_type = "incident.resolved" if data.status in ("resolved", "closed") else "incident.updated"
        dispatch_event(event_type, {
            "id": incident.id, "changes": changes,
            "status": incident.status.value if incident.status else None,
        }, auth.org_id, db)

    return {
        "id": incident.id,
        "status": incident.status.value if incident.status else None,
        "severity": incident.severity.value if incident.severity else None,
        "updated_at": incident.updated_at.isoformat(),
    }
