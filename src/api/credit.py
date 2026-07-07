"""AI Credit Underwriting Oversight endpoints.

Sits between a bank's credit-decisioning AI and the final decision. For every
inbound decision:

  1. Runs GovernLayer's patent-compliant risk score (Factor 2 = confidence,
     Factor 3 = "credit_denial" use-case, Factor 4 = vulnerable population).
  2. Maps model feature attributions to ECOA Regulation B reason codes
     (see src/credit/reason_codes.py).
  3. Flags protected-class proxy contributions for fair-lending review.
  4. Escalates borderline denials (confidence < 0.85) to a Compliance Officer
     via the HITL SLA engine using ViolationType.ECOA.
  5. Writes the outcome (with reason codes and fair-lending flags) to the
     hash-chained audit ledger so it can survive a CFPB / OCC exam.

Companion endpoint /credit/sr26-2/{system_name} emits an SR 26-2 / OCC 2026-13
model risk management document from the same underlying data. The legacy
/credit/sr11-7/{system_name} path is retained as a deprecated alias for
existing clients — it returns identical content plus a Deprecation header.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.risk import compute_patent_risk
from src.config import get_settings
from src.credit.reason_codes import (
    AdverseActionResult,
    pick_reason_codes,
    catalog as reason_code_catalog,
)
from src.credit.mrm import generate_mrm, to_dict as mrm_to_dict
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
router = APIRouter(prefix="/credit", tags=["credit"])
settings = get_settings()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreditDecisionRequest(BaseModel):
    """A credit-decisioning AI's proposed decision for oversight."""

    system_name: str = Field(..., min_length=1, max_length=255,
                             description="Name of the upstream decisioning model")
    application_id: str = Field(..., min_length=1, max_length=128,
                                description="Bank-side loan application ID")

    proposed_decision: str = Field(
        ...,
        pattern=r"^(approve|deny|counter_offer)$",
        description="What the model wants to do: approve, deny, counter_offer",
    )
    model_confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Model confidence in the proposed decision (0-1)",
    )

    # Feature attributions — {feature_name: contribution toward denial}.
    # Positive = pushed toward denial. This is where the fair-lending signal lives.
    feature_attributions: dict[str, float] = Field(
        default_factory=dict,
        description="SHAP-style feature -> contribution (positive = pushed toward denial)",
    )

    # Applicant / product context (used by Factor 3 + Factor 4 scoring)
    loan_type: str = Field(default="unsecured_consumer", max_length=64,
                           description="unsecured_consumer, mortgage, auto, small_business, etc.")
    requested_amount: Optional[float] = Field(default=None, ge=0)
    applicant_income: Optional[float] = Field(default=None, ge=0)
    applicant_age: Optional[int] = Field(default=None, ge=0, le=150)

    # Optional policy violations pre-flagged by upstream systems
    policy_violations: list[PolicyViolation] = Field(default_factory=list)

    creditor_name: Optional[str] = Field(default=None, max_length=255,
                                         description="Creditor name for the adverse-action statement")


class CreditOversightResponse(BaseModel):
    decision_id: str
    application_id: str
    system_name: str
    governance_action: str      # APPROVE_PASSTHROUGH | ESCALATE_HUMAN | BLOCK | DENY_WITH_NOTICE
    reason: str
    risk_score: float
    risk_level: str
    escalation: Optional[dict] = None
    adverse_action: Optional[dict] = None
    fair_lending_flags: list[str] = Field(default_factory=list)
    current_hash: str
    policy_version: str
    timestamp: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


CONFIDENCE_ESCALATION_THRESHOLD = 0.85


def _serialise_reasons(aa: AdverseActionResult) -> dict:
    return {
        "reason_codes": [
            {"code": rc.code, "statement": rc.statement, "source": rc.source}
            for rc in aa.reason_codes
        ],
        "unmatched_features": aa.unmatched_features,
        "protected_class_flags": aa.protected_class_flags,
        "statement": aa.statement,
        "ecoa_compliant": aa.ecoa_compliant,
        "warnings": aa.warnings,
    }


@router.post("/oversight", response_model=CreditOversightResponse)
def credit_oversight(
    request: CreditDecisionRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Oversight for a single AI credit decision.

    Pipeline:
      confidence / vulnerable-population -> risk score
      denial -> adverse-action reason-code generation (Reg B)
      protected-class proxy -> fair-lending flag
      borderline denial or HIGH+ risk -> HITL escalation (ECOA queue, 4h SLA)
      always -> hash-chained ledger append
    """
    # ---- Risk score ---------------------------------------------------------
    is_adverse = request.proposed_decision in ("deny", "counter_offer")
    risk_req = PatentRiskScoreRequest(
        system_name=request.system_name,
        policy_violations=request.policy_violations,
        ai_confidence=request.model_confidence,
        use_case="credit_denial" if is_adverse else "loan",
        subject_income=request.applicant_income,
        subject_age=request.applicant_age,
        adverse_action=is_adverse,
    )
    composite, risk_level, factors = compute_patent_risk(risk_req)

    # ---- Adverse-action reasons (only for denials) --------------------------
    adverse_result: Optional[AdverseActionResult] = None
    if request.proposed_decision == "deny":
        adverse_result = pick_reason_codes(
            request.feature_attributions,
            creditor_name=request.creditor_name,
        )

    fair_lending_flags: list[str] = (
        adverse_result.protected_class_flags if adverse_result else []
    )

    # ---- Governance decision ------------------------------------------------
    # Rules, most-restrictive first:
    #   1. Fair-lending proxy detected on a denial -> BLOCK, no notice sent.
    #   2. CRITICAL risk -> BLOCK.
    #   3. Denial with reason-code compliance failure -> ESCALATE_HUMAN.
    #   4. Borderline denial (confidence < 0.85) -> ESCALATE_HUMAN.
    #   5. HIGH risk on an adverse action -> ESCALATE_HUMAN.
    #   6. Otherwise -> APPROVE_PASSTHROUGH (approvals or clean, defensible denials).
    escalation_dict: Optional[dict] = None

    if fair_lending_flags:
        action = "BLOCK"
        reason = (
            "BLOCKED: fair-lending exposure — protected-class proxy attributes contributed "
            "to the denial (" + ", ".join(fair_lending_flags) + "). Denial cannot be sent "
            "to the applicant until fair-lending review clears the decision."
        )
    elif risk_level == "CRITICAL":
        action = "BLOCK"
        reason = f"BLOCKED: composite risk {composite:.2f} is CRITICAL."
    elif adverse_result and not adverse_result.ecoa_compliant and request.proposed_decision == "deny":
        action = "ESCALATE_HUMAN"
        reason = (
            "ESCALATED: denial reasons do not meet Reg B specificity requirements. "
            + " ".join(adverse_result.warnings)
        )
    elif is_adverse and request.model_confidence < CONFIDENCE_ESCALATION_THRESHOLD:
        action = "ESCALATE_HUMAN"
        reason = (
            f"ESCALATED: borderline adverse action — model confidence "
            f"{request.model_confidence:.2f} below threshold "
            f"{CONFIDENCE_ESCALATION_THRESHOLD}. Requires underwriter review."
        )
    elif risk_level == "HIGH" and is_adverse:
        action = "ESCALATE_HUMAN"
        reason = (
            f"ESCALATED: HIGH composite risk {composite:.2f} on an adverse action. "
            "Requires Compliance Officer review."
        )
    elif request.proposed_decision == "deny":
        action = "DENY_WITH_NOTICE"
        reason = "Denial approved to proceed with Reg B adverse-action notice attached."
    else:
        action = "APPROVE_PASSTHROUGH"
        reason = (
            f"Approval passed through oversight. Composite risk {composite:.2f} ({risk_level})."
        )

    # ---- HITL escalation ----------------------------------------------------
    decision_id = str(uuid.uuid4())
    if action == "ESCALATE_HUMAN":
        esc = route_escalation(
            decision_id=decision_id,
            violations=["ECOA"],
            risk_level=risk_level,
        )
        escalation_dict = escalation_to_dict(esc)

    # ---- Ledger append ------------------------------------------------------
    previous_hash = get_last_hash(db)
    record_payload = {
        "decision_id": decision_id,
        "application_id": request.application_id,
        "system_name": request.system_name,
        "proposed_decision": request.proposed_decision,
        "governance_action": action,
        "risk_score": composite,
        "risk_level": risk_level,
        "factors": [
            {
                "factor": f.factor,
                "weight": f.weight,
                "raw_contribution": f.raw_contribution,
                "weighted_contribution": f.weighted_contribution,
            }
            for f in factors
        ],
        "adverse_action": _serialise_reasons(adverse_result) if adverse_result else None,
        "fair_lending_flags": fair_lending_flags,
        "policy_version": settings.policy_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    current_hash = compute_hash({**record_payload, "previous_hash": previous_hash})

    audit = AuditRecord(
        decision_id=decision_id,
        system_name=request.system_name,
        industry="banking:credit",
        audited_by=email,
        frameworks_audited="ECOA,REG_B,SR_26_2,OCC_2026_13,FCRA",
        results=json.dumps({"reason": reason, **record_payload}),
        risk_score=composite,
        risk_level=risk_level,
        governance_action=action,
        policy_version=settings.policy_version,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(audit)
    log_mutation(
        db, email, "create", "credit_oversight_decision", decision_id,
        f"{action}: app={request.application_id} model={request.system_name} "
        f"risk={composite:.2f} conf={request.model_confidence:.2f}"
    )
    db.commit()

    # ---- Webhook fan-out ----------------------------------------------------
    try:
        from src.api.webhooks import dispatch_event
        dispatch_event(
            f"credit.{action.lower()}",
            {
                "decision_id": decision_id,
                "application_id": request.application_id,
                "system": request.system_name,
                "action": action,
                "risk_score": composite,
                "risk_level": risk_level,
                "fair_lending_flags": fair_lending_flags,
            },
            None, db,
        )
    except Exception as e:  # noqa: BLE001 — never break oversight on webhook bugs
        logger.warning("credit oversight webhook dispatch failed: %s", e)

    return CreditOversightResponse(
        decision_id=decision_id,
        application_id=request.application_id,
        system_name=request.system_name,
        governance_action=action,
        reason=reason,
        risk_score=round(composite, 4),
        risk_level=risk_level,
        escalation=escalation_dict,
        adverse_action=_serialise_reasons(adverse_result) if adverse_result else None,
        fair_lending_flags=fair_lending_flags,
        current_hash=current_hash,
        policy_version=settings.policy_version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/reason-codes")
def list_reason_codes(email: str = Depends(verify_token)):
    """Return the full published catalog of Reg B adverse-action reason codes."""
    return {
        "count": len(reason_code_catalog()),
        "reason_codes": [
            {"code": rc.code, "statement": rc.statement, "source": rc.source}
            for rc in reason_code_catalog()
        ],
    }


def _build_mrm_document(
    system_name: str,
    window_days: int,
    generated_for: str,
    db: Session,
) -> dict:
    if not system_name.strip():
        raise HTTPException(status_code=400, detail="system_name is required")
    doc = generate_mrm(
        db,
        system_name=system_name,
        generated_for=generated_for,
        window_days=window_days,
    )
    return mrm_to_dict(doc)


@router.get("/sr26-2/{system_name}")
def sr26_2_document(
    system_name: str,
    window_days: int = 90,
    generated_for: str = "Bank Model Risk Management",
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Generate an SR 26-2 / OCC 2026-13 model risk management document.

    SR 26-2 (Federal Reserve) and OCC Bulletin 2026-13 replaced SR 11-7 on
    2026-04-17, extending model-risk expectations to AI/ML systems including
    generative models, agentic systems, and third-party AI. The document
    covers §III inventory, §V.1 conceptual soundness, §V.3 ongoing monitoring
    (drift + kill-switch evidence), §V.4 outcomes analysis, and §VII
    governance / policies / controls.

    Query params:
        window_days: Reporting window (default 90)
        generated_for: Recipient / bank name for the document header
    """
    return _build_mrm_document(system_name, window_days, generated_for, db)


@router.get("/sr11-7/{system_name}", deprecated=True)
def sr11_7_document_deprecated(
    system_name: str,
    response: Response,
    window_days: int = 90,
    generated_for: str = "Bank Model Risk Management",
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Deprecated alias for /credit/sr26-2/{system_name}.

    SR 11-7 was rescinded and replaced by SR 26-2 (Federal Reserve) + OCC
    Bulletin 2026-13 on 2026-04-17. This endpoint is retained for clients
    that pinned the SR 11-7 path; new integrations should call /credit/sr26-2.
    Sets RFC 8594 Deprecation and Sunset headers.
    """
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Wed, 31 Dec 2026 23:59:59 GMT"
    response.headers["Link"] = (
        '</credit/sr26-2/' + system_name + '>; rel="successor-version"'
    )
    return _build_mrm_document(system_name, window_days, generated_for, db)
