"""GovernLayer Compliance Calendar API.

Tracks audit windows, certification renewals, control reviews, regulatory
deadlines, and other compliance milestones.  Uses in-memory storage with
demo seed data so the API is functional without a database.
"""

import uuid
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/calendar", tags=["Compliance Calendar"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    audit_window = "audit_window"
    certification_renewal = "certification_renewal"
    control_review = "control_review"
    regulatory_deadline = "regulatory_deadline"
    training_due = "training_due"
    access_review = "access_review"
    pentest = "pentest"
    vendor_review = "vendor_review"
    custom = "custom"


class Recurrence(str, Enum):
    none = "none"
    monthly = "monthly"
    quarterly = "quarterly"
    annually = "annually"


class EventStatus(str, Enum):
    upcoming = "upcoming"
    in_progress = "in_progress"
    completed = "completed"
    overdue = "overdue"


class Priority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class Reminder(BaseModel):
    days_before: int = Field(..., ge=0, description="Days before the event to trigger a reminder")
    sent: bool = False


class CalendarEventCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field("", max_length=2048)
    event_type: EventType
    framework: Optional[str] = Field(None, max_length=64, examples=["SOC2", "GDPR", "ISO27001"])
    date: str = Field(..., description="ISO date string (YYYY-MM-DD)")
    end_date: Optional[str] = Field(None, description="ISO date string (YYYY-MM-DD)")
    recurring: Recurrence = Recurrence.none
    status: EventStatus = EventStatus.upcoming
    assignee: EmailStr
    priority: Priority = Priority.medium
    reminders: list[Reminder] = Field(default_factory=list)


class CalendarEventUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=2048)
    event_type: Optional[EventType] = None
    framework: Optional[str] = Field(None, max_length=64)
    date: Optional[str] = None
    end_date: Optional[str] = None
    recurring: Optional[Recurrence] = None
    status: Optional[EventStatus] = None
    assignee: Optional[EmailStr] = None
    priority: Optional[Priority] = None
    reminders: Optional[list[Reminder]] = None


class CalendarEvent(BaseModel):
    id: str
    title: str
    description: str
    event_type: EventType
    framework: Optional[str]
    date: str
    end_date: Optional[str]
    recurring: Recurrence
    status: EventStatus
    assignee: str
    priority: Priority
    reminders: list[Reminder]
    created_by: str
    created_at: str


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_events: dict[str, dict] = {}
_seeded: bool = False


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _iso(d: date) -> str:
    return d.isoformat()


def _parse_date(s: str) -> date:
    try:
        return date.fromisoformat(s)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid date format: {s!r}. Expected YYYY-MM-DD.") from exc


def _seed_events() -> None:
    """Populate the store with realistic compliance demo events."""
    global _seeded
    if _seeded:
        return
    _seeded = True

    now = _today()
    seed_email = "compliance@governlayer.ai"
    created_at = datetime.now(timezone.utc).isoformat()

    demos: list[dict] = [
        {
            "title": "SOC 2 Type II Audit Window",
            "description": "Annual SOC 2 Type II audit observation period. Auditors on-site for evidence collection.",
            "event_type": EventType.audit_window,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=14)),
            "end_date": _iso(now + timedelta(days=44)),
            "recurring": Recurrence.annually,
            "priority": Priority.critical,
            "assignee": seed_email,
            "reminders": [{"days_before": 30, "sent": False}, {"days_before": 7, "sent": False}],
        },
        {
            "title": "ISO 27001 Surveillance Audit",
            "description": "Annual surveillance audit by certification body to maintain ISO 27001 certification.",
            "event_type": EventType.certification_renewal,
            "framework": "ISO27001",
            "date": _iso(now + timedelta(days=60)),
            "recurring": Recurrence.annually,
            "priority": Priority.critical,
            "assignee": seed_email,
            "reminders": [{"days_before": 45, "sent": False}, {"days_before": 14, "sent": False}],
        },
        {
            "title": "Q3 Access Review",
            "description": "Quarterly review of user access rights across production systems.",
            "event_type": EventType.access_review,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=30)),
            "recurring": Recurrence.quarterly,
            "priority": Priority.high,
            "assignee": seed_email,
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "Annual Penetration Test",
            "description": "External penetration test of production infrastructure and APIs.",
            "event_type": EventType.pentest,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=45)),
            "end_date": _iso(now + timedelta(days=52)),
            "recurring": Recurrence.annually,
            "priority": Priority.critical,
            "assignee": "security@governlayer.ai",
            "reminders": [{"days_before": 30, "sent": False}, {"days_before": 7, "sent": False}],
        },
        {
            "title": "GDPR Data Protection Officer Review",
            "description": "DPO quarterly review of data processing activities and DPIA register.",
            "event_type": EventType.regulatory_deadline,
            "framework": "GDPR",
            "date": _iso(now + timedelta(days=20)),
            "recurring": Recurrence.quarterly,
            "priority": Priority.high,
            "assignee": "dpo@governlayer.ai",
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "Security Awareness Training Renewal",
            "description": "Annual security awareness training for all staff. Required for SOC 2 and ISO 27001.",
            "event_type": EventType.training_due,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=75)),
            "recurring": Recurrence.annually,
            "priority": Priority.medium,
            "assignee": "hr@governlayer.ai",
            "reminders": [{"days_before": 30, "sent": False}, {"days_before": 7, "sent": False}],
        },
        {
            "title": "Vendor Risk Assessment - Cloud Providers",
            "description": "Annual review of critical vendor security posture and SOC 2 reports.",
            "event_type": EventType.vendor_review,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=90)),
            "recurring": Recurrence.annually,
            "priority": Priority.high,
            "assignee": seed_email,
            "reminders": [{"days_before": 21, "sent": False}],
        },
        {
            "title": "HIPAA Risk Assessment",
            "description": "Annual HIPAA security risk assessment for healthcare data handling.",
            "event_type": EventType.audit_window,
            "framework": "HIPAA",
            "date": _iso(now + timedelta(days=120)),
            "end_date": _iso(now + timedelta(days=134)),
            "recurring": Recurrence.annually,
            "priority": Priority.high,
            "assignee": seed_email,
            "reminders": [{"days_before": 30, "sent": False}],
        },
        {
            "title": "EU AI Act Compliance Check",
            "description": "Review AI systems against EU AI Act risk classification and transparency requirements.",
            "event_type": EventType.regulatory_deadline,
            "framework": "EU_AI_ACT",
            "date": _iso(now + timedelta(days=35)),
            "recurring": Recurrence.quarterly,
            "priority": Priority.high,
            "assignee": seed_email,
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "Quarterly Control Effectiveness Review",
            "description": "Review effectiveness of security controls against policy objectives.",
            "event_type": EventType.control_review,
            "framework": "ISO27001",
            "date": _iso(now + timedelta(days=50)),
            "recurring": Recurrence.quarterly,
            "priority": Priority.medium,
            "assignee": seed_email,
            "reminders": [{"days_before": 7, "sent": False}],
        },
        {
            "title": "Vendor Risk Assessment - SaaS Tools",
            "description": "Review security posture of SaaS vendors (Slack, Jira, GitHub, etc.).",
            "event_type": EventType.vendor_review,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=105)),
            "recurring": Recurrence.annually,
            "priority": Priority.medium,
            "assignee": seed_email,
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "NIST AI RMF Self-Assessment",
            "description": "Self-assessment against NIST AI Risk Management Framework profiles.",
            "event_type": EventType.control_review,
            "framework": "NIST_AI_RMF",
            "date": _iso(now + timedelta(days=70)),
            "recurring": Recurrence.annually,
            "priority": Priority.medium,
            "assignee": seed_email,
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "Privacy Impact Assessment Review",
            "description": "Review and update Data Protection Impact Assessments for high-risk processing.",
            "event_type": EventType.regulatory_deadline,
            "framework": "GDPR",
            "date": _iso(now + timedelta(days=150)),
            "recurring": Recurrence.annually,
            "priority": Priority.high,
            "assignee": "dpo@governlayer.ai",
            "reminders": [{"days_before": 30, "sent": False}],
        },
        {
            "title": "Incident Response Plan Tabletop Exercise",
            "description": "Simulated incident response exercise to test IR procedures and communication plans.",
            "event_type": EventType.training_due,
            "framework": "SOC2",
            "date": _iso(now + timedelta(days=55)),
            "recurring": Recurrence.annually,
            "priority": Priority.medium,
            "assignee": "security@governlayer.ai",
            "reminders": [{"days_before": 14, "sent": False}],
        },
        {
            "title": "Overdue: Business Continuity Plan Review",
            "description": "Annual BCP/DRP review and update. Was due last quarter.",
            "event_type": EventType.control_review,
            "framework": "ISO27001",
            "date": _iso(now - timedelta(days=15)),
            "recurring": Recurrence.annually,
            "status": EventStatus.overdue,
            "priority": Priority.critical,
            "assignee": seed_email,
            "reminders": [{"days_before": 30, "sent": True}, {"days_before": 7, "sent": True}],
        },
    ]

    for item in demos:
        event_id = str(uuid.uuid4())
        _events[event_id] = {
            "id": event_id,
            "title": item["title"],
            "description": item["description"],
            "event_type": item["event_type"].value,
            "framework": item.get("framework"),
            "date": item["date"],
            "end_date": item.get("end_date"),
            "recurring": item.get("recurring", Recurrence.none).value,
            "status": item.get("status", EventStatus.upcoming).value,
            "assignee": item["assignee"],
            "priority": item.get("priority", Priority.medium).value,
            "reminders": [r if isinstance(r, dict) else r.dict() for r in item.get("reminders", [])],
            "created_by": "system",
            "created_at": created_at,
        }


def _ensure_seeded() -> None:
    if not _seeded:
        _seed_events()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auto_mark_overdue() -> None:
    """Mark events whose date has passed and status is not completed."""
    today = _today()
    for evt in _events.values():
        if evt["status"] in (EventStatus.upcoming.value, EventStatus.in_progress.value):
            if _parse_date(evt["date"]) < today:
                evt["status"] = EventStatus.overdue.value


def _matches_month(evt: dict, month: str) -> bool:
    """Check if event falls within a YYYY-MM month."""
    try:
        year, mon = month.split("-")
        year, mon = int(year), int(mon)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail=f"Invalid month format: {month!r}. Expected YYYY-MM.")
    evt_date = _parse_date(evt["date"])
    if evt_date.year == year and evt_date.month == mon:
        return True
    end = evt.get("end_date")
    if end:
        end_date = _parse_date(end)
        first_of_month = date(year, mon, 1)
        last_of_month = date(year, mon + 1, 1) - timedelta(days=1) if mon < 12 else date(year, 12, 31)
        if evt_date <= last_of_month and end_date >= first_of_month:
            return True
    return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
def list_events(
    month: Optional[str] = Query(None, description="Filter by month (YYYY-MM)"),
    event_type: Optional[EventType] = Query(None, description="Filter by event type"),
    framework: Optional[str] = Query(None, description="Filter by framework (e.g. SOC2, GDPR)"),
    status: Optional[EventStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Maximum events to return"),
    email: str = Depends(verify_token),
):
    """List compliance calendar events with optional filters."""
    _ensure_seeded()
    _auto_mark_overdue()

    results = list(_events.values())

    if month:
        results = [e for e in results if _matches_month(e, month)]
    if event_type:
        results = [e for e in results if e["event_type"] == event_type.value]
    if framework:
        results = [e for e in results if e.get("framework") and e["framework"].upper() == framework.upper()]
    if status:
        results = [e for e in results if e["status"] == status.value]

    results.sort(key=lambda e: e["date"])
    results = results[:limit]

    return {"total": len(results), "events": results}


@router.post("", status_code=201)
def create_event(
    body: CalendarEventCreate,
    email: str = Depends(verify_token),
):
    """Create a new compliance calendar event."""
    _ensure_seeded()

    _parse_date(body.date)
    if body.end_date:
        end = _parse_date(body.end_date)
        if end < _parse_date(body.date):
            raise HTTPException(status_code=422, detail="end_date must be on or after date.")

    event_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    event = {
        "id": event_id,
        "title": body.title,
        "description": body.description,
        "event_type": body.event_type.value,
        "framework": body.framework,
        "date": body.date,
        "end_date": body.end_date,
        "recurring": body.recurring.value,
        "status": body.status.value,
        "assignee": body.assignee,
        "priority": body.priority.value,
        "reminders": [r.model_dump() for r in body.reminders],
        "created_by": email,
        "created_at": now_iso,
    }

    _events[event_id] = event
    return event


@router.get("/upcoming")
def upcoming_events(
    email: str = Depends(verify_token),
):
    """Return events in the next 30 days plus any currently overdue items, sorted by date."""
    _ensure_seeded()
    _auto_mark_overdue()

    today = _today()
    horizon = today + timedelta(days=30)

    results = []
    for evt in _events.values():
        evt_date = _parse_date(evt["date"])
        if evt["status"] == EventStatus.overdue.value:
            results.append(evt)
        elif today <= evt_date <= horizon:
            results.append(evt)

    results.sort(key=lambda e: e["date"])
    return {"total": len(results), "events": results}


@router.get("/overdue")
def overdue_events(
    email: str = Depends(verify_token),
):
    """Return all overdue events (date in the past and not completed)."""
    _ensure_seeded()
    _auto_mark_overdue()

    today = _today()
    results = [
        evt for evt in _events.values()
        if _parse_date(evt["date"]) < today and evt["status"] != EventStatus.completed.value
    ]
    results.sort(key=lambda e: e["date"])
    return {"total": len(results), "events": results}


@router.get("/summary")
def calendar_summary(
    email: str = Depends(verify_token),
):
    """Monthly summary: events by type, overdue count, next 5 upcoming events."""
    _ensure_seeded()
    _auto_mark_overdue()

    today = _today()
    all_events = list(_events.values())

    # Events by type
    by_type: dict[str, int] = {}
    for evt in all_events:
        t = evt["event_type"]
        by_type[t] = by_type.get(t, 0) + 1

    # Overdue count
    overdue_count = sum(
        1 for evt in all_events
        if evt["status"] == EventStatus.overdue.value
        or (_parse_date(evt["date"]) < today and evt["status"] != EventStatus.completed.value)
    )

    # Next 5 upcoming (date >= today, not completed)
    upcoming = [
        evt for evt in all_events
        if _parse_date(evt["date"]) >= today and evt["status"] != EventStatus.completed.value
    ]
    upcoming.sort(key=lambda e: e["date"])
    next_five = upcoming[:5]

    # Events this month
    this_month = f"{today.year}-{today.month:02d}"
    this_month_count = sum(1 for evt in all_events if _matches_month(evt, this_month))

    return {
        "total_events": len(all_events),
        "this_month": this_month_count,
        "overdue_count": overdue_count,
        "events_by_type": by_type,
        "next_upcoming": next_five,
    }


@router.get("/{event_id}")
def get_event(
    event_id: str,
    email: str = Depends(verify_token),
):
    """Retrieve a single compliance calendar event by ID."""
    _ensure_seeded()
    _auto_mark_overdue()

    event = _events.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Calendar event not found.")
    return event


@router.patch("/{event_id}")
def update_event(
    event_id: str,
    body: CalendarEventUpdate,
    email: str = Depends(verify_token),
):
    """Update fields on an existing compliance calendar event."""
    _ensure_seeded()

    event = _events.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Calendar event not found.")

    updates = body.model_dump(exclude_unset=True)

    if "date" in updates:
        _parse_date(updates["date"])
    if "end_date" in updates and updates["end_date"] is not None:
        _parse_date(updates["end_date"])

    effective_date = updates.get("date", event["date"])
    effective_end = updates.get("end_date", event.get("end_date"))
    if effective_end is not None and _parse_date(effective_end) < _parse_date(effective_date):
        raise HTTPException(status_code=422, detail="end_date must be on or after date.")

    for key, value in updates.items():
        if key == "reminders" and value is not None:
            event["reminders"] = [r.model_dump() if hasattr(r, "model_dump") else r for r in value]
        elif isinstance(value, Enum):
            event[key] = value.value
        else:
            event[key] = value

    return event


@router.delete("/{event_id}", status_code=204)
def delete_event(
    event_id: str,
    email: str = Depends(verify_token),
):
    """Delete a compliance calendar event."""
    _ensure_seeded()

    if event_id not in _events:
        raise HTTPException(status_code=404, detail="Calendar event not found.")
    del _events[event_id]
    return None
