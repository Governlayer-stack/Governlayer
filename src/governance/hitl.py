"""HITL SLA Deadline Engine — violation-based routing with SLA enforcement.

Patent-compliant human-in-the-loop escalation system. Maps regulatory violations
to qualified reviewers with legally mandated SLA deadlines:

    sla_deadline = current_time + delta_t(violation_type, risk_level)

Violation routing:
    ECOA  -> Compliance Officer (Finance), 4h SLA
    EEOC  -> HR Compliance Officer, 4h SLA
    HIPAA -> Licensed Medical Professional, 2h SLA
    HIGH-risk general  -> Senior Reviewer, 8h SLA
    MEDIUM-risk general -> Standard Queue, 24h SLA
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class EscalationStatus(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ViolationType(str, Enum):
    ECOA = "ECOA"
    EEOC = "EEOC"
    HIPAA = "HIPAA"
    GENERAL = "GENERAL"


@dataclass
class EscalationRequest:
    """A single HITL escalation with SLA tracking."""
    decision_id: str
    violation_type: ViolationType
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    assigned_reviewer: str
    sla_deadline: datetime
    status: EscalationStatus = EscalationStatus.PENDING
    justification: str = ""
    escalation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


# ---------------------------------------------------------------------------
# Routing table: violation_type -> (reviewer_role, sla_hours)
# ---------------------------------------------------------------------------

_VIOLATION_ROUTING: dict[ViolationType, tuple[str, int]] = {
    ViolationType.ECOA: ("Compliance Officer (Finance)", 4),
    ViolationType.EEOC: ("HR Compliance Officer", 4),
    ViolationType.HIPAA: ("Licensed Medical Professional", 2),
}

_RISK_ROUTING: dict[str, tuple[str, int]] = {
    "CRITICAL": ("Senior Reviewer", 4),
    "HIGH": ("Senior Reviewer", 8),
    "MEDIUM": ("Standard Queue", 24),
    "LOW": ("Standard Queue", 48),
}


# ---------------------------------------------------------------------------
# In-memory store (production: database-backed)
# ---------------------------------------------------------------------------

_escalations: dict[str, EscalationRequest] = {}
_store_lock = threading.Lock()


def _store_escalation(esc: EscalationRequest) -> None:
    with _store_lock:
        _escalations[esc.escalation_id] = esc


def _get_escalation(escalation_id: str) -> Optional[EscalationRequest]:
    with _store_lock:
        return _escalations.get(escalation_id)


def _list_escalations(status: Optional[EscalationStatus] = None) -> list[EscalationRequest]:
    with _store_lock:
        if status is None:
            return list(_escalations.values())
        return [e for e in _escalations.values() if e.status == status]


# ---------------------------------------------------------------------------
# Core engine functions
# ---------------------------------------------------------------------------

def route_escalation(
    decision_id: str,
    violations: list[str],
    risk_level: str,
) -> EscalationRequest:
    """Map violations to the correct reviewer and compute the SLA deadline.

    If multiple violations are present, the most restrictive SLA wins
    (shortest deadline). The reviewer is chosen from the most critical
    violation type.

    Args:
        decision_id: The governance decision that triggered escalation.
        violations: List of violation type strings (e.g. ["ECOA", "HIPAA"]).
        risk_level: Overall risk level (LOW, MEDIUM, HIGH, CRITICAL).

    Returns:
        A persisted EscalationRequest with computed SLA deadline.
    """
    now = datetime.now(timezone.utc)
    best_reviewer: Optional[str] = None
    shortest_hours: int = 9999

    # Check specific violation types first
    for v in violations:
        vtype = ViolationType(v.upper()) if v.upper() in ViolationType.__members__ else None
        if vtype and vtype in _VIOLATION_ROUTING:
            reviewer, hours = _VIOLATION_ROUTING[vtype]
            if hours < shortest_hours:
                shortest_hours = hours
                best_reviewer = reviewer

    # Determine the primary violation type for the record
    violation_type = ViolationType.GENERAL
    for v in violations:
        upper = v.upper()
        if upper in ViolationType.__members__:
            violation_type = ViolationType(upper)
            break

    # Fall back to risk-based routing if no specific violation matched
    if best_reviewer is None:
        risk_key = risk_level.upper()
        reviewer, hours = _RISK_ROUTING.get(risk_key, ("Standard Queue", 24))
        best_reviewer = reviewer
        shortest_hours = hours
    else:
        # If we have a violation-based reviewer, still consider risk-based SLA
        # if risk level is more urgent (e.g. CRITICAL overrides ECOA 4h -> 4h)
        risk_key = risk_level.upper()
        if risk_key in _RISK_ROUTING:
            _, risk_hours = _RISK_ROUTING[risk_key]
            if risk_hours < shortest_hours:
                shortest_hours = risk_hours

    sla_deadline = now + timedelta(hours=shortest_hours)

    esc = EscalationRequest(
        decision_id=decision_id,
        violation_type=violation_type,
        risk_level=risk_level.upper(),
        assigned_reviewer=best_reviewer,
        sla_deadline=sla_deadline,
    )
    _store_escalation(esc)

    logger.info(
        "Escalation created: id=%s decision=%s reviewer=%s sla=%sh deadline=%s",
        esc.escalation_id[:8], decision_id[:8], best_reviewer,
        shortest_hours, sla_deadline.isoformat(),
    )
    return esc


def check_sla_compliance(escalation_id: str) -> dict:
    """Check whether an escalation's SLA deadline has been exceeded.

    Returns:
        Dict with sla_status (compliant/breached/resolved), remaining time,
        and escalation details.

    Raises:
        ValueError: If escalation_id is not found.
    """
    esc = _get_escalation(escalation_id)
    if esc is None:
        raise ValueError(f"Escalation {escalation_id} not found")

    now = datetime.now(timezone.utc)

    # Already resolved — report final status
    if esc.status in (EscalationStatus.APPROVED, EscalationStatus.REJECTED):
        resolved_within = (
            (esc.resolved_at - esc.created_at).total_seconds()
            if esc.resolved_at else None
        )
        sla_total = (esc.sla_deadline - esc.created_at).total_seconds()
        return {
            "escalation_id": esc.escalation_id,
            "sla_status": "resolved",
            "resolution": esc.status.value,
            "resolved_within_seconds": resolved_within,
            "sla_budget_seconds": sla_total,
            "sla_met": resolved_within is not None and resolved_within <= sla_total,
        }

    # Check if expired
    if now > esc.sla_deadline:
        with _store_lock:
            esc.status = EscalationStatus.EXPIRED
        return {
            "escalation_id": esc.escalation_id,
            "sla_status": "breached",
            "exceeded_by_seconds": (now - esc.sla_deadline).total_seconds(),
            "assigned_reviewer": esc.assigned_reviewer,
            "violation_type": esc.violation_type.value,
        }

    remaining = (esc.sla_deadline - now).total_seconds()
    return {
        "escalation_id": esc.escalation_id,
        "sla_status": "compliant",
        "remaining_seconds": remaining,
        "assigned_reviewer": esc.assigned_reviewer,
        "status": esc.status.value,
    }


def resolve_escalation(
    escalation_id: str,
    reviewer_id: str,
    decision: str,
    justification: str = "",
) -> EscalationRequest:
    """Record a human reviewer's decision on an escalation.

    CRITICAL-risk decisions require a non-empty justification.

    Args:
        escalation_id: The escalation to resolve.
        reviewer_id: Identifier of the human reviewer.
        decision: "approved" or "rejected".
        justification: Required for CRITICAL-risk escalations.

    Returns:
        Updated EscalationRequest.

    Raises:
        ValueError: If escalation not found, invalid decision, or missing
            justification on CRITICAL-risk decisions.
    """
    esc = _get_escalation(escalation_id)
    if esc is None:
        raise ValueError(f"Escalation {escalation_id} not found")

    decision_lower = decision.lower()
    if decision_lower not in ("approved", "rejected"):
        raise ValueError(f"Invalid decision '{decision}'. Must be 'approved' or 'rejected'.")

    if esc.risk_level == "CRITICAL" and not justification.strip():
        raise ValueError(
            "CRITICAL-risk decisions require documented justification. "
            "Provide a non-empty justification string."
        )

    if esc.status in (EscalationStatus.APPROVED, EscalationStatus.REJECTED):
        raise ValueError(
            f"Escalation {escalation_id} already resolved with status '{esc.status.value}'."
        )

    now = datetime.now(timezone.utc)
    with _store_lock:
        esc.status = EscalationStatus(decision_lower)
        esc.justification = justification
        esc.resolved_at = now
        esc.resolved_by = reviewer_id

    logger.info(
        "Escalation resolved: id=%s reviewer=%s decision=%s sla_met=%s",
        esc.escalation_id[:8], reviewer_id, decision_lower,
        now <= esc.sla_deadline,
    )
    return esc


def get_sla_dashboard() -> dict:
    """Return an overview of all escalations grouped by SLA compliance status."""
    now = datetime.now(timezone.utc)
    pending = []
    breached = []
    resolved = []

    with _store_lock:
        for esc in _escalations.values():
            entry = {
                "escalation_id": esc.escalation_id,
                "decision_id": esc.decision_id,
                "violation_type": esc.violation_type.value,
                "risk_level": esc.risk_level,
                "assigned_reviewer": esc.assigned_reviewer,
                "status": esc.status.value,
                "sla_deadline": esc.sla_deadline.isoformat(),
                "created_at": esc.created_at.isoformat(),
            }

            if esc.status in (EscalationStatus.APPROVED, EscalationStatus.REJECTED):
                entry["resolved_at"] = esc.resolved_at.isoformat() if esc.resolved_at else None
                entry["resolved_by"] = esc.resolved_by
                entry["sla_met"] = (
                    esc.resolved_at <= esc.sla_deadline if esc.resolved_at else False
                )
                resolved.append(entry)
            elif now > esc.sla_deadline:
                entry["exceeded_by_seconds"] = (now - esc.sla_deadline).total_seconds()
                breached.append(entry)
            else:
                entry["remaining_seconds"] = (esc.sla_deadline - now).total_seconds()
                pending.append(entry)

    return {
        "total": len(pending) + len(breached) + len(resolved),
        "pending": pending,
        "breached": breached,
        "resolved": resolved,
        "summary": {
            "pending_count": len(pending),
            "breached_count": len(breached),
            "resolved_count": len(resolved),
        },
    }


def escalation_to_dict(esc: EscalationRequest) -> dict:
    """Serialize an EscalationRequest to a JSON-safe dict."""
    return {
        "escalation_id": esc.escalation_id,
        "decision_id": esc.decision_id,
        "violation_type": esc.violation_type.value,
        "risk_level": esc.risk_level,
        "assigned_reviewer": esc.assigned_reviewer,
        "sla_deadline": esc.sla_deadline.isoformat(),
        "status": esc.status.value,
        "justification": esc.justification,
        "created_at": esc.created_at.isoformat(),
        "resolved_at": esc.resolved_at.isoformat() if esc.resolved_at else None,
        "resolved_by": esc.resolved_by,
    }
