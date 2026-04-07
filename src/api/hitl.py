"""HITL SLA Deadline Engine — API endpoints.

Provides REST endpoints for the patent-compliant human-in-the-loop escalation
system with violation-based routing and SLA enforcement.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.governance.hitl import (
    EscalationStatus,
    check_sla_compliance,
    escalation_to_dict,
    get_sla_dashboard,
    resolve_escalation,
    route_escalation,
    _list_escalations,
)
from src.security.auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hitl", tags=["hitl"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class EscalateRequest(BaseModel):
    """Request to create a new HITL escalation."""
    decision_id: str = Field(..., min_length=1, max_length=64, description="Governance decision ID")
    violations: list[str] = Field(
        default_factory=list,
        description="Violation types: ECOA, EEOC, HIPAA, GENERAL",
    )
    risk_level: str = Field(
        default="MEDIUM",
        pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$",
        description="Risk level: LOW, MEDIUM, HIGH, CRITICAL",
    )


class ResolveRequest(BaseModel):
    """Request to resolve an escalation with a human decision."""
    reviewer_id: str = Field(..., min_length=1, max_length=255, description="Reviewer identifier")
    decision: str = Field(
        ...,
        pattern=r"^(approved|rejected)$",
        description="Human decision: approved or rejected",
    )
    justification: str = Field(
        default="",
        max_length=5000,
        description="Required for CRITICAL-risk decisions",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/escalate")
def create_escalation(
    request: EscalateRequest,
    email: str = Depends(verify_token),
):
    """Create a new HITL escalation with violation-based routing and SLA deadline.

    Routes the decision to the appropriate reviewer based on violation type
    and risk level, computing the SLA deadline as:

        sla_deadline = current_time + delta_t(violation_type, risk_level)
    """
    violations = request.violations if request.violations else ["GENERAL"]
    try:
        esc = route_escalation(
            decision_id=request.decision_id,
            violations=violations,
            risk_level=request.risk_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status": "escalated",
        "escalation": escalation_to_dict(esc),
        "escalated_by": email,
    }


@router.get("/queue")
def list_queue(
    status: Optional[str] = None,
    email: str = Depends(verify_token),
):
    """List pending escalations (or filter by status).

    Query params:
        status: Optional filter — pending, in_review, approved, rejected, expired
    """
    filter_status = None
    if status:
        try:
            filter_status = EscalationStatus(status.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{status}'. Valid: pending, in_review, approved, rejected, expired",
            )

    escalations = _list_escalations(filter_status)
    return {
        "count": len(escalations),
        "escalations": [escalation_to_dict(e) for e in escalations],
    }


@router.post("/resolve/{escalation_id}")
def resolve(
    escalation_id: str,
    request: ResolveRequest,
    email: str = Depends(verify_token),
):
    """Resolve an escalation with a human reviewer's decision.

    CRITICAL-risk decisions require a non-empty justification field.
    """
    try:
        esc = resolve_escalation(
            escalation_id=escalation_id,
            reviewer_id=request.reviewer_id,
            decision=request.decision,
            justification=request.justification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status": "resolved",
        "escalation": escalation_to_dict(esc),
        "resolved_by": email,
    }


@router.get("/sla-status")
def sla_status(email: str = Depends(verify_token)):
    """SLA compliance dashboard — overview of all escalations by compliance status.

    Returns counts and details for pending, breached, and resolved escalations.
    """
    return get_sla_dashboard()
