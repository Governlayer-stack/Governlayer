import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.config import get_settings
from src.drift.detection import analyze_reasoning
from src.models.database import AuditRecord, compute_hash, get_db, get_last_hash
from src.models.schemas import GovernRequest
from src.security.auth import verify_token

router = APIRouter(tags=["governance"])
settings = get_settings()


def compute_risk_scores(request: GovernRequest) -> dict:
    return {
        "Privacy": 100 if not request.handles_personal_data else 40,
        "Autonomy_Risk": 100 if not request.makes_autonomous_decisions else 30,
        "Infrastructure_Risk": 100 if not request.used_in_critical_infrastructure else 25,
        "Oversight": 100 if request.has_human_oversight else 20,
        "Transparency": 100 if request.is_explainable else 30,
        "Fairness": 100 if request.has_bias_testing else 25,
    }


@router.post("/govern")
def govern_decision(request: GovernRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    drift_result = analyze_reasoning(reasoning_trace=request.reasoning_trace, use_case=request.use_case)
    scores = compute_risk_scores(request)
    overall_risk = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall_risk >= 80 else "MEDIUM" if overall_risk >= 50 else "HIGH"

    if drift_result["vetoed"]:
        governance_action = "BLOCK"
        dc = drift_result['drift_coefficient']
        reason = f"BLOCKED: Behavioral drift detected. D_c={dc} exceeds threshold. {drift_result['explanation']}"
    elif risk_level == "HIGH":
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: High risk score {round(overall_risk)}/100. Requires human review."
    elif risk_level == "MEDIUM" and drift_result["semantic_risk_flags"] > 0:
        governance_action = "ESCALATE_HUMAN"
        reason = f"ESCALATED: Medium risk with {drift_result['semantic_risk_flags']} semantic risk flags."
    else:
        governance_action = "APPROVE"
        dc = drift_result['drift_coefficient']
        reason = f"APPROVED: Risk score {round(overall_risk)}/100. Drift coefficient {dc} within safe boundaries."

    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {
        "decision_id": decision_id,
        "system_name": request.system_name,
        "governance_action": governance_action,
        "drift_coefficient": drift_result["drift_coefficient"],
        "risk_score": overall_risk,
        "policy_version": settings.policy_version,
        "created_at": datetime.utcnow().isoformat(),
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})

    audit = AuditRecord(
        decision_id=decision_id, system_name=request.system_name, industry=request.use_case,
        audited_by=email, frameworks_audited="NIST_AI_RMF,EU_AI_ACT,ISO_42001", results=reason,
        risk_score=overall_risk, risk_level=risk_level, governance_action=governance_action,
        policy_version=settings.policy_version, previous_hash=previous_hash, current_hash=current_hash,
    )
    db.add(audit)
    db.commit()

    return {
        "decision_id": decision_id, "system": request.system_name,
        "governance_action": governance_action, "reason": reason,
        "drift_analysis": drift_result, "risk_score": round(overall_risk),
        "risk_level": risk_level, "dimension_scores": scores,
        "current_hash": current_hash, "policy_version": settings.policy_version,
        "timestamp": datetime.utcnow().isoformat(),
    }
