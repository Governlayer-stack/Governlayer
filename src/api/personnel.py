"""Personnel Management API -- employee lifecycle tracking for compliance.

Enterprise compliance frameworks (SOC 2, ISO 27001) require tracking:
- Employee onboarding/offboarding
- Background checks
- Security awareness training
- Periodic access reviews
- Equipment assignment and recovery
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

from src.security.auth import verify_token

router = APIRouter(prefix="/v1/personnel", tags=["Personnel"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class BackgroundCheck(BaseModel):
    status: str = Field(default="pending", pattern=r"^(pending|in_progress|passed|failed)$")
    completed_at: Optional[str] = None
    provider: Optional[str] = None


class SecurityTraining(BaseModel):
    completed: bool = False
    completed_at: Optional[str] = None
    expires_at: Optional[str] = None
    score: Optional[float] = Field(default=None, ge=0, le=100)


class AccessReview(BaseModel):
    reviewed_at: str
    reviewer: str
    result: str = Field(..., pattern=r"^(approved|revoked|needs_action)$")
    notes: Optional[str] = None


class Equipment(BaseModel):
    type: str
    asset_id: str
    status: str = Field(default="assigned", pattern=r"^(assigned|returned|lost|decommissioned)$")


class PersonRecord(BaseModel):
    id: str
    email: str
    name: str
    role: str
    department: str
    status: str
    hire_date: str
    termination_date: Optional[str] = None
    background_check: BackgroundCheck
    security_training: SecurityTraining
    access_reviews: list[AccessReview]
    equipment: list[Equipment]


class CreatePersonRequest(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=255)
    role: str = Field(..., min_length=1, max_length=255)
    department: str = Field(..., min_length=1, max_length=255)
    status: str = Field(default="active", pattern=r"^(active|pending)$")
    hire_date: Optional[str] = None
    equipment: list[Equipment] = Field(default_factory=list)


class UpdatePersonRequest(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    role: Optional[str] = Field(default=None, min_length=1, max_length=255)
    department: Optional[str] = Field(default=None, min_length=1, max_length=255)
    status: Optional[str] = Field(
        default=None, pattern=r"^(active|offboarding|offboarded|pending)$"
    )


class RecordTrainingRequest(BaseModel):
    score: float = Field(..., ge=0, le=100)
    provider: str = Field(default="internal", max_length=255)
    validity_days: int = Field(default=365, ge=1, le=1095)


class RecordBackgroundCheckRequest(BaseModel):
    status: str = Field(..., pattern=r"^(passed|failed|in_progress)$")
    provider: str = Field(..., max_length=255)


class RecordAccessReviewRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=255)
    result: str = Field(..., pattern=r"^(approved|revoked|needs_action)$")
    notes: Optional[str] = Field(default=None, max_length=2000)


# ---------------------------------------------------------------------------
# In-memory store + seed data
# ---------------------------------------------------------------------------

_personnel_store: dict[str, dict] = {}
_seeded: bool = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_data() -> None:
    """Populate demo personnel so the dashboard is never empty on first access."""
    global _seeded
    if _seeded:
        return
    _seeded = True

    now = datetime.now(timezone.utc)
    six_months_ago = (now - timedelta(days=180)).isoformat()
    one_year_ago = (now - timedelta(days=365)).isoformat()
    two_years_ago = (now - timedelta(days=730)).isoformat()
    three_months_ago = (now - timedelta(days=90)).isoformat()
    one_month_ago = (now - timedelta(days=30)).isoformat()
    training_expiry = (now + timedelta(days=180)).isoformat()
    training_expired = (now - timedelta(days=30)).isoformat()

    seed = [
        {
            "email": "alice.chen@governlayer.ai",
            "name": "Alice Chen",
            "role": "Security Engineer",
            "department": "Engineering",
            "status": "active",
            "hire_date": two_years_ago,
            "background_check": {"status": "passed", "completed_at": two_years_ago, "provider": "Checkr"},
            "security_training": {"completed": True, "completed_at": three_months_ago, "expires_at": training_expiry, "score": 95.0},
            "access_reviews": [
                {"reviewed_at": one_month_ago, "reviewer": "bob.martinez@governlayer.ai", "result": "approved", "notes": "Full access appropriate for role"}
            ],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-001", "status": "assigned"},
                {"type": "yubikey", "asset_id": "GL-YK-012", "status": "assigned"},
            ],
        },
        {
            "email": "bob.martinez@governlayer.ai",
            "name": "Bob Martinez",
            "role": "VP of Engineering",
            "department": "Engineering",
            "status": "active",
            "hire_date": two_years_ago,
            "background_check": {"status": "passed", "completed_at": two_years_ago, "provider": "Checkr"},
            "security_training": {"completed": True, "completed_at": six_months_ago, "expires_at": training_expiry, "score": 88.0},
            "access_reviews": [
                {"reviewed_at": one_month_ago, "reviewer": "carol.okafor@governlayer.ai", "result": "approved", "notes": "Admin access verified"}
            ],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-002", "status": "assigned"},
            ],
        },
        {
            "email": "carol.okafor@governlayer.ai",
            "name": "Carol Okafor",
            "role": "Compliance Lead",
            "department": "Legal & Compliance",
            "status": "active",
            "hire_date": one_year_ago,
            "background_check": {"status": "passed", "completed_at": one_year_ago, "provider": "Sterling"},
            "security_training": {"completed": True, "completed_at": three_months_ago, "expires_at": training_expiry, "score": 100.0},
            "access_reviews": [
                {"reviewed_at": one_month_ago, "reviewer": "bob.martinez@governlayer.ai", "result": "approved", "notes": "Compliance tools access confirmed"}
            ],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-003", "status": "assigned"},
                {"type": "yubikey", "asset_id": "GL-YK-015", "status": "assigned"},
            ],
        },
        {
            "email": "david.kim@governlayer.ai",
            "name": "David Kim",
            "role": "Backend Developer",
            "department": "Engineering",
            "status": "active",
            "hire_date": six_months_ago,
            "background_check": {"status": "passed", "completed_at": six_months_ago, "provider": "Checkr"},
            "security_training": {"completed": True, "completed_at": six_months_ago, "expires_at": training_expired, "score": 82.0},
            "access_reviews": [],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-007", "status": "assigned"},
            ],
        },
        {
            "email": "elena.rossi@governlayer.ai",
            "name": "Elena Rossi",
            "role": "Data Analyst",
            "department": "Product",
            "status": "offboarding",
            "hire_date": one_year_ago,
            "background_check": {"status": "passed", "completed_at": one_year_ago, "provider": "Sterling"},
            "security_training": {"completed": True, "completed_at": one_year_ago, "expires_at": training_expired, "score": 76.0},
            "access_reviews": [
                {"reviewed_at": three_months_ago, "reviewer": "carol.okafor@governlayer.ai", "result": "revoked", "notes": "Offboarding -- access revoked"}
            ],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-005", "status": "assigned"},
                {"type": "monitor", "asset_id": "GL-MON-009", "status": "assigned"},
            ],
        },
        {
            "email": "frank.nguyen@governlayer.ai",
            "name": "Frank Nguyen",
            "role": "Sales Director",
            "department": "Sales",
            "status": "active",
            "hire_date": one_year_ago,
            "background_check": {"status": "pending", "completed_at": None, "provider": None},
            "security_training": {"completed": False, "completed_at": None, "expires_at": None, "score": None},
            "access_reviews": [],
            "equipment": [
                {"type": "laptop", "asset_id": "GL-LAP-006", "status": "assigned"},
            ],
        },
        {
            "email": "grace.patel@governlayer.ai",
            "name": "Grace Patel",
            "role": "DevOps Engineer",
            "department": "Engineering",
            "status": "pending",
            "hire_date": now.isoformat(),
            "background_check": {"status": "in_progress", "completed_at": None, "provider": "Checkr"},
            "security_training": {"completed": False, "completed_at": None, "expires_at": None, "score": None},
            "access_reviews": [],
            "equipment": [],
        },
    ]

    for person_data in seed:
        person_id = str(uuid.uuid4())
        _personnel_store[person_id] = {
            "id": person_id,
            "termination_date": None,
            **person_data,
        }


def _ensure_seeded() -> None:
    if not _seeded:
        _seed_data()


def _get_person_or_404(person_id: str) -> dict:
    _ensure_seeded()
    person = _personnel_store.get(person_id)
    if person is None:
        raise HTTPException(status_code=404, detail=f"Person {person_id} not found")
    return person


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/compliance/summary")
def compliance_summary(_email: str = Depends(verify_token)):
    """Overall compliance posture across all personnel.

    Returns training completion rate, background check completion rate,
    access review coverage, and counts of overdue items.
    """
    _ensure_seeded()
    now = datetime.now(timezone.utc)
    people = list(_personnel_store.values())
    active = [p for p in people if p["status"] in ("active", "pending")]
    total_active = len(active) or 1  # avoid division by zero

    training_complete = sum(1 for p in active if p["security_training"]["completed"])
    bg_check_done = sum(
        1 for p in active if p["background_check"]["status"] in ("passed", "failed")
    )
    has_recent_review = 0
    for p in active:
        if p["access_reviews"]:
            latest = max(p["access_reviews"], key=lambda r: r["reviewed_at"])
            reviewed_dt = datetime.fromisoformat(latest["reviewed_at"])
            if reviewed_dt.tzinfo is None:
                reviewed_dt = reviewed_dt.replace(tzinfo=timezone.utc)
            if (now - reviewed_dt).days <= 90:
                has_recent_review += 1

    overdue = _compute_overdue(people, now)

    return {
        "total_personnel": len(people),
        "active_personnel": len(active),
        "training_completion_pct": round(training_complete / total_active * 100, 1),
        "background_check_completion_pct": round(bg_check_done / total_active * 100, 1),
        "access_review_coverage_pct": round(has_recent_review / total_active * 100, 1),
        "overdue_items_count": len(overdue),
        "by_category": {
            "expired_training": len([i for i in overdue if i["type"] == "expired_training"]),
            "missing_background_check": len([i for i in overdue if i["type"] == "missing_background_check"]),
            "overdue_access_review": len([i for i in overdue if i["type"] == "overdue_access_review"]),
        },
        "generated_at": _now_iso(),
    }


@router.get("/compliance/overdue")
def compliance_overdue(_email: str = Depends(verify_token)):
    """List all overdue compliance items across personnel.

    Checks for expired or missing security training, incomplete background
    checks, and access reviews older than 90 days.
    """
    _ensure_seeded()
    now = datetime.now(timezone.utc)
    people = list(_personnel_store.values())
    overdue = _compute_overdue(people, now)

    return {
        "total_overdue": len(overdue),
        "items": overdue,
        "generated_at": _now_iso(),
    }


def _compute_overdue(people: list[dict], now: datetime) -> list[dict]:
    """Shared logic for computing overdue compliance items."""
    overdue = []
    for p in people:
        if p["status"] in ("offboarded",):
            continue

        # Expired or missing training
        training = p["security_training"]
        if not training["completed"]:
            overdue.append({
                "type": "missing_training",
                "person_id": p["id"],
                "person_name": p["name"],
                "email": p["email"],
                "department": p["department"],
                "detail": "Security training not completed",
            })
        elif training.get("expires_at"):
            exp_dt = datetime.fromisoformat(training["expires_at"])
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < now:
                overdue.append({
                    "type": "expired_training",
                    "person_id": p["id"],
                    "person_name": p["name"],
                    "email": p["email"],
                    "department": p["department"],
                    "detail": f"Training expired on {training['expires_at']}",
                })

        # Missing background check
        bg = p["background_check"]
        if bg["status"] in ("pending",) and p["status"] != "pending":
            overdue.append({
                "type": "missing_background_check",
                "person_id": p["id"],
                "person_name": p["name"],
                "email": p["email"],
                "department": p["department"],
                "detail": f"Background check still {bg['status']}",
            })

        # Overdue access review (active employees should have a review within 90 days)
        if p["status"] == "active":
            if not p["access_reviews"]:
                overdue.append({
                    "type": "overdue_access_review",
                    "person_id": p["id"],
                    "person_name": p["name"],
                    "email": p["email"],
                    "department": p["department"],
                    "detail": "No access review on record",
                })
            else:
                latest = max(p["access_reviews"], key=lambda r: r["reviewed_at"])
                reviewed_dt = datetime.fromisoformat(latest["reviewed_at"])
                if reviewed_dt.tzinfo is None:
                    reviewed_dt = reviewed_dt.replace(tzinfo=timezone.utc)
                if (now - reviewed_dt).days > 90:
                    overdue.append({
                        "type": "overdue_access_review",
                        "person_id": p["id"],
                        "person_name": p["name"],
                        "email": p["email"],
                        "department": p["department"],
                        "detail": f"Last review was {(now - reviewed_dt).days} days ago",
                    })

    return overdue


@router.get("")
def list_personnel(
    status: Optional[str] = Query(default=None, pattern=r"^(active|offboarding|offboarded|pending)$"),
    department: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _email: str = Depends(verify_token),
):
    """List all personnel with optional filtering by status and department."""
    _ensure_seeded()
    people = list(_personnel_store.values())

    if status:
        people = [p for p in people if p["status"] == status]
    if department:
        people = [p for p in people if p["department"].lower() == department.lower()]

    # Compute aggregations before applying limit
    by_status: dict[str, int] = {}
    by_department: dict[str, int] = {}
    for p in people:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
        by_department[p["department"]] = by_department.get(p["department"], 0) + 1

    return {
        "total": len(people),
        "by_status": by_status,
        "by_department": by_department,
        "personnel": people[:limit],
    }


@router.post("", status_code=201)
def create_person(req: CreatePersonRequest, _email: str = Depends(verify_token)):
    """Onboard a new person. Creates the personnel record with initial compliance state."""
    _ensure_seeded()

    # Check for duplicate email
    for p in _personnel_store.values():
        if p["email"] == req.email:
            raise HTTPException(status_code=409, detail=f"Person with email {req.email} already exists")

    person_id = str(uuid.uuid4())
    now = _now_iso()
    person = {
        "id": person_id,
        "email": req.email,
        "name": req.name,
        "role": req.role,
        "department": req.department,
        "status": req.status,
        "hire_date": req.hire_date or now,
        "termination_date": None,
        "background_check": {"status": "pending", "completed_at": None, "provider": None},
        "security_training": {"completed": False, "completed_at": None, "expires_at": None, "score": None},
        "access_reviews": [],
        "equipment": [eq.model_dump() for eq in req.equipment],
    }
    _personnel_store[person_id] = person

    return person


@router.get("/{person_id}")
def get_person(person_id: str, _email: str = Depends(verify_token)):
    """Get full details for a single person including compliance state."""
    return _get_person_or_404(person_id)


@router.patch("/{person_id}")
def update_person(person_id: str, req: UpdatePersonRequest, _email: str = Depends(verify_token)):
    """Update mutable fields on a personnel record."""
    person = _get_person_or_404(person_id)
    updates = req.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    if "email" in updates:
        # Check for duplicate email
        for p in _personnel_store.values():
            if p["email"] == updates["email"] and p["id"] != person_id:
                raise HTTPException(status_code=409, detail=f"Email {updates['email']} already in use")

    person.update(updates)
    return person


@router.post("/{person_id}/offboard")
def offboard_person(person_id: str, _email: str = Depends(verify_token)):
    """Initiate the offboarding process for a person.

    Returns a compliance-grade offboarding checklist with current status
    for each required step: access revocation, equipment collection,
    and exit interview.
    """
    person = _get_person_or_404(person_id)

    if person["status"] == "offboarded":
        raise HTTPException(status_code=400, detail="Person is already offboarded")

    now = _now_iso()
    person["status"] = "offboarding"
    person["termination_date"] = now

    # Build offboarding checklist
    equipment_items = []
    for eq in person["equipment"]:
        equipment_items.append({
            "type": eq["type"],
            "asset_id": eq["asset_id"],
            "current_status": eq["status"],
            "action_required": eq["status"] == "assigned",
        })

    has_active_access = True
    if person["access_reviews"]:
        latest = max(person["access_reviews"], key=lambda r: r["reviewed_at"])
        if latest["result"] == "revoked":
            has_active_access = False

    checklist = {
        "person_id": person_id,
        "person_name": person["name"],
        "initiated_at": now,
        "status": "offboarding",
        "steps": [
            {
                "step": "revoke_access",
                "description": "Revoke all system and application access",
                "status": "pending" if has_active_access else "completed",
                "required": True,
            },
            {
                "step": "collect_equipment",
                "description": "Collect all assigned equipment",
                "status": "pending" if any(eq["status"] == "assigned" for eq in person["equipment"]) else "completed",
                "required": True,
                "items": equipment_items,
            },
            {
                "step": "exit_interview",
                "description": "Conduct exit interview and document findings",
                "status": "pending",
                "required": True,
            },
            {
                "step": "knowledge_transfer",
                "description": "Ensure documentation and knowledge transfer is complete",
                "status": "pending",
                "required": True,
            },
            {
                "step": "final_payroll",
                "description": "Process final payroll and benefits termination",
                "status": "pending",
                "required": True,
            },
        ],
        "completed_steps": 0,
        "total_steps": 5,
    }

    # Count already-completed steps
    checklist["completed_steps"] = sum(
        1 for s in checklist["steps"] if s["status"] == "completed"
    )

    return checklist


@router.post("/{person_id}/training")
def record_training(person_id: str, req: RecordTrainingRequest, _email: str = Depends(verify_token)):
    """Record completion of security awareness training for a person."""
    person = _get_person_or_404(person_id)
    now = datetime.now(timezone.utc)

    person["security_training"] = {
        "completed": True,
        "completed_at": now.isoformat(),
        "expires_at": (now + timedelta(days=req.validity_days)).isoformat(),
        "score": req.score,
    }

    return {
        "person_id": person_id,
        "person_name": person["name"],
        "training": person["security_training"],
        "provider": req.provider,
        "message": "Security training recorded successfully",
    }


@router.post("/{person_id}/background-check")
def record_background_check(
    person_id: str, req: RecordBackgroundCheckRequest, _email: str = Depends(verify_token)
):
    """Record the result of a background check for a person."""
    person = _get_person_or_404(person_id)
    now = _now_iso()

    person["background_check"] = {
        "status": req.status,
        "completed_at": now if req.status in ("passed", "failed") else None,
        "provider": req.provider,
    }

    return {
        "person_id": person_id,
        "person_name": person["name"],
        "background_check": person["background_check"],
        "message": f"Background check recorded as {req.status}",
    }


@router.post("/{person_id}/access-review")
def record_access_review(
    person_id: str, req: RecordAccessReviewRequest, _email: str = Depends(verify_token)
):
    """Record an access review for a person. Required quarterly for SOC 2 / ISO 27001."""
    person = _get_person_or_404(person_id)
    now = _now_iso()

    review = {
        "reviewed_at": now,
        "reviewer": req.reviewer,
        "result": req.result,
        "notes": req.notes,
    }
    person["access_reviews"].append(review)

    return {
        "person_id": person_id,
        "person_name": person["name"],
        "review": review,
        "total_reviews": len(person["access_reviews"]),
        "message": f"Access review recorded: {req.result}",
    }
