"""Fraud & AML Decision Escalation endpoints.

Sits between a bank's fraud / AML AI and any customer-visible action
(freeze, block, close, hold). For every proposed action:

  1. Computes the impact score using the new consumer-harm use-case categories
     (account_freeze, account_close, transaction_block) added to Factor 3.
  2. Escalates low-confidence or high-impact actions to an analyst via the
     HITL SLA engine using ViolationType.BSA_AML for AML/BSA-driven actions
     and ViolationType.UDAAP for consumer-harm risk.
  3. Records the human-in-the-loop review to the hash-chained audit ledger
     so BSA/AML examiners have a defensible record.

Rule of thumb: the fraud AI is fast but wrong sometimes. GovernLayer's job
is to make sure "sometimes" doesn't reach the customer without an analyst.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.risk import compute_patent_risk
from src.config import get_settings
from src.governance.hitl import (
    escalation_to_dict,
    route_escalation,
)
from src.models.database import (
    AuditRecord,
    compute_hash,
    get_db,
    get_last_hash,
    log_mutation,
)
from src.models.schemas import PatentRiskScoreRequest, PolicyViolation
from src.security.auth import verify_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/fraud", tags=["fraud"])
settings = get_settings()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


PROPOSED_ACTIONS = ("account_freeze", "account_close", "transaction_block", "manual_review", "hold")


class FraudActionRequest(BaseModel):
    """A fraud/AML AI's proposed action for oversight."""

    system_name: str = Field(..., min_length=1, max_length=255)
    subject_id: str = Field(..., min_length=1, max_length=128,
                            description="Customer / account / transaction ID being acted on")

    proposed_action: str = Field(
        ...,
        pattern=r"^(account_freeze|account_close|transaction_block|manual_review|hold)$",
        description="What the model wants to do",
    )
    action_reason: str = Field(
        ..., min_length=1, max_length=500,
        description="Model's stated reason (SAR trigger, sanctions hit, velocity, etc.)",
    )
    model_confidence: float = Field(..., ge=0.0, le=1.0)

    # Impact fields help the analyst make a call and are recorded in the ledger
    customer_balance: Optional[float] = Field(default=None, ge=0,
                                              description="Balance affected — drives UDAAP risk")
    transaction_amount: Optional[float] = Field(default=None, ge=0)
    aml_typology: Optional[str] = Field(
        default=None, max_length=128,
        description="e.g. structuring, layering, sanctions_hit, PEP, elder_financial_abuse",
    )
    prior_action_count_30d: int = Field(
        default=0, ge=0,
        description="Number of similar restrictive actions on this customer in the last 30 days "
                    "(repeat action = higher UDAAP exposure)",
    )
    applicant_income: Optional[float] = Field(default=None, ge=0)
    applicant_age: Optional[int] = Field(default=None, ge=0, le=150)

    policy_violations: list[PolicyViolation] = Field(default_factory=list)


class FraudEscalationResponse(BaseModel):
    decision_id: str
    subject_id: str
    system_name: str
    governance_action: str      # ALLOW_ACTION | ESCALATE_ANALYST | HOLD_ACTION | BLOCK_ACTION
    reason: str
    risk_score: float
    risk_level: str
    violation_routing: list[str]
    escalation: Optional[dict] = None
    current_hash: str
    policy_version: str
    timestamp: str


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


CONFIDENCE_ESCALATION_THRESHOLD = 0.85

# AML typologies that must always land with a BSA/AML officer, regardless of confidence
_AML_ALWAYS_ESCALATE = {
    "sanctions_hit", "pep", "elder_financial_abuse", "human_trafficking",
}


@router.post("/escalation", response_model=FraudEscalationResponse)
def fraud_escalation(
    request: FraudActionRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Oversight for a proposed fraud/AML action.

    Pipeline:
      risk score (confidence + consumer-harm use case + vulnerable population)
      typology check (some always route to BSA/AML officer)
      confidence gate (< 0.85 -> analyst)
      repeat-action gate (>= 3 in 30d -> UDAAP escalation)
      -> HITL routing (BSA_AML and/or UDAAP)
      -> hash-chained ledger append
    """
    # ---- Risk score ---------------------------------------------------------
    is_consumer_harm = request.proposed_action in ("account_freeze", "account_close", "transaction_block")
    risk_req = PatentRiskScoreRequest(
        system_name=request.system_name,
        policy_violations=request.policy_violations,
        ai_confidence=request.model_confidence,
        use_case=request.proposed_action if is_consumer_harm else "general",
        subject_income=request.applicant_income,
        subject_age=request.applicant_age,
        adverse_action=is_consumer_harm,
    )
    composite, risk_level, factors = compute_patent_risk(risk_req)

    # ---- Violation routing --------------------------------------------------
    violations: list[str] = []
    if request.aml_typology:
        violations.append("BSA_AML")
    if is_consumer_harm and (
        request.model_confidence < CONFIDENCE_ESCALATION_THRESHOLD
        or request.prior_action_count_30d >= 3
    ):
        violations.append("UDAAP")

    # ---- Governance decision ------------------------------------------------
    reasons: list[str] = []
    action: str

    typology_forced = (
        request.aml_typology is not None
        and request.aml_typology.lower() in _AML_ALWAYS_ESCALATE
    )

    if risk_level == "CRITICAL":
        action = "BLOCK_ACTION"
        reasons.append(f"CRITICAL composite risk {composite:.2f}.")
    elif typology_forced:
        action = "ESCALATE_ANALYST"
        reasons.append(
            f"AML typology '{request.aml_typology}' always requires BSA officer review."
        )
    elif is_consumer_harm and request.model_confidence < CONFIDENCE_ESCALATION_THRESHOLD:
        action = "ESCALATE_ANALYST"
        reasons.append(
            f"Model confidence {request.model_confidence:.2f} below threshold "
            f"{CONFIDENCE_ESCALATION_THRESHOLD} on a consumer-harm action."
        )
    elif is_consumer_harm and request.prior_action_count_30d >= 3:
        action = "ESCALATE_ANALYST"
        reasons.append(
            f"Repeat restrictive action ({request.prior_action_count_30d} in 30d) "
            "elevates UDAAP exposure."
        )
    elif risk_level == "HIGH" and is_consumer_harm:
        action = "HOLD_ACTION"
        reasons.append(
            f"HIGH composite risk {composite:.2f} on a consumer-harm action — hold 15 min "
            "for out-of-band contact before executing."
        )
    else:
        action = "ALLOW_ACTION"
        reasons.append(
            f"Composite risk {composite:.2f} ({risk_level}); model confidence "
            f"{request.model_confidence:.2f} within tolerance."
        )

    reason_text = " ".join(reasons)

    # ---- HITL escalation ----------------------------------------------------
    decision_id = str(uuid.uuid4())
    escalation_dict: Optional[dict] = None
    if action == "ESCALATE_ANALYST":
        routed = violations or ["GENERAL"]
        esc = route_escalation(
            decision_id=decision_id,
            violations=routed,
            risk_level=risk_level,
        )
        escalation_dict = escalation_to_dict(esc)

    # ---- Ledger append ------------------------------------------------------
    previous_hash = get_last_hash(db)
    record_payload = {
        "decision_id": decision_id,
        "subject_id": request.subject_id,
        "system_name": request.system_name,
        "proposed_action": request.proposed_action,
        "action_reason": request.action_reason,
        "governance_action": action,
        "risk_score": composite,
        "risk_level": risk_level,
        "violation_routing": violations,
        "typology": request.aml_typology,
        "prior_action_count_30d": request.prior_action_count_30d,
        "customer_balance": request.customer_balance,
        "transaction_amount": request.transaction_amount,
        "policy_version": settings.policy_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    current_hash = compute_hash({**record_payload, "previous_hash": previous_hash})

    audit = AuditRecord(
        decision_id=decision_id,
        system_name=request.system_name,
        industry="banking:fraud_aml",
        audited_by=email,
        frameworks_audited="BSA,BSA_AML,UDAAP,OFAC",
        results=json.dumps({"reason": reason_text, **record_payload}),
        risk_score=composite,
        risk_level=risk_level,
        governance_action=action,
        policy_version=settings.policy_version,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(audit)
    log_mutation(
        db, email, "create", "fraud_escalation_decision", decision_id,
        f"{action}: subject={request.subject_id} typology={request.aml_typology} "
        f"conf={request.model_confidence:.2f} risk={composite:.2f}"
    )
    db.commit()

    # ---- Webhook fan-out ----------------------------------------------------
    try:
        from src.api.webhooks import dispatch_event
        dispatch_event(
            f"fraud.{action.lower()}",
            {
                "decision_id": decision_id,
                "subject_id": request.subject_id,
                "system": request.system_name,
                "action": action,
                "risk_score": composite,
                "risk_level": risk_level,
                "violation_routing": violations,
            },
            None, db,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("fraud escalation webhook dispatch failed: %s", e)

    return FraudEscalationResponse(
        decision_id=decision_id,
        subject_id=request.subject_id,
        system_name=request.system_name,
        governance_action=action,
        reason=reason_text,
        risk_score=round(composite, 4),
        risk_level=risk_level,
        violation_routing=violations,
        escalation=escalation_dict,
        current_hash=current_hash,
        policy_version=settings.policy_version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
