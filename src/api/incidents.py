"""Incident Management API — full lifecycle tracking."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.models.database import SessionLocal
from src.models.registry import Incident, IncidentSeverity, IncidentStatus

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
def create_incident(data: IncidentCreate):
    """Report a new AI governance incident."""
    db = SessionLocal()
    try:
        incident = Incident(
            title=data.title,
            description=data.description,
            model_id=data.model_id,
            severity=IncidentSeverity(data.severity),
            category=data.category,
            reporter=data.reporter,
            timeline=[{"timestamp": datetime.utcnow().isoformat(), "action": "created", "actor": data.reporter or "system"}],
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
        }
    finally:
        db.close()


@router.get("")
def list_incidents(status: Optional[str] = None, severity: Optional[str] = None):
    """List all incidents with optional filters."""
    db = SessionLocal()
    try:
        query = db.query(Incident)
        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        incidents = query.order_by(Incident.created_at.desc()).all()
        return {
            "total": len(incidents),
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
    finally:
        db.close()


@router.get("/{incident_id}")
def get_incident(incident_id: int):
    """Get detailed incident information."""
    db = SessionLocal()
    try:
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
    finally:
        db.close()


@router.patch("/{incident_id}")
def update_incident(incident_id: int, data: IncidentUpdate):
    """Update incident status, assignment, or resolution."""
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        timeline_entry = {"timestamp": datetime.utcnow().isoformat(), "actor": "system"}

        if data.status:
            valid = [e.value for e in IncidentStatus]
            if data.status not in valid:
                raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid}")
            incident.status = IncidentStatus(data.status)
            timeline_entry["action"] = f"status changed to {data.status}"
            if data.status in ("resolved", "closed"):
                incident.resolved_at = datetime.utcnow()

        if data.severity:
            incident.severity = IncidentSeverity(data.severity)
            timeline_entry["action"] = f"severity changed to {data.severity}"

        if data.assignee:
            incident.assignee = data.assignee
            timeline_entry["action"] = f"assigned to {data.assignee}"

        if data.root_cause:
            incident.root_cause = data.root_cause
        if data.resolution:
            incident.resolution = data.resolution
        if data.impact:
            incident.impact = data.impact

        incident.timeline = (incident.timeline or []) + [timeline_entry]
        incident.updated_at = datetime.utcnow()
        db.commit()

        return {
            "id": incident.id,
            "status": incident.status.value if incident.status else None,
            "severity": incident.severity.value if incident.severity else None,
            "updated_at": incident.updated_at.isoformat(),
        }
    finally:
        db.close()
