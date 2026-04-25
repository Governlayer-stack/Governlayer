"""GovernLayer API v1 — versioned endpoints for enterprise consumers.

All endpoints use API key auth (gl_xxx) or JWT.
Enterprises integrate with these stable, versioned routes.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.api.webhooks import dispatch_event
from src.config import get_settings
from src.drift.detection import analyze_reasoning
from src.models.database import AuditRecord, compute_hash, get_db, get_last_hash
from src.models.schemas import DriftRequest, GovernRequest, RiskScoreRequest
from src.security.api_key_auth import AuthContext, require_org, require_scope

settings = get_settings()

router = APIRouter(prefix="/v1", tags=["v1 — Enterprise API"])


# --- Governance Decision ---

def _require_org_and_scope(scope: str):
    """Require both org membership and a specific scope."""
    def checker(auth: AuthContext = Depends(require_org)):
        if not auth.has_scope(scope):
            raise HTTPException(status_code=403, detail=f"Missing required scope: {scope}")
        return auth
    return checker


@router.post("/govern")
def govern(request: GovernRequest, auth: AuthContext = Depends(_require_org_and_scope("govern")),
           db: Session = Depends(get_db)):
    """Run the full governance pipeline: drift detection + risk scoring + decision + ledger entry.

    Returns APPROVE, ESCALATE_HUMAN, or BLOCK with full audit trail.
    """
    drift_result = analyze_reasoning(reasoning_trace=request.reasoning_trace, use_case=request.use_case)

    scores = {
        "privacy": 100 if not request.handles_personal_data else 40,
        "autonomy": 100 if not request.makes_autonomous_decisions else 30,
        "infrastructure": 100 if not request.used_in_critical_infrastructure else 25,
        "oversight": 100 if request.has_human_oversight else 20,
        "transparency": 100 if request.is_explainable else 30,
        "fairness": 100 if request.has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"

    if drift_result["vetoed"]:
        action, reason = "BLOCK", f"Behavioral drift detected (D_c={drift_result['drift_coefficient']})"
    elif risk_level == "HIGH":
        action, reason = "ESCALATE_HUMAN", f"High risk score ({round(overall)}/100)"
    elif risk_level == "MEDIUM" and drift_result["semantic_risk_flags"] > 0:
        action, reason = "ESCALATE_HUMAN", f"Medium risk with {drift_result['semantic_risk_flags']} semantic flags"
    else:
        dc = drift_result['drift_coefficient']
        action, reason = "APPROVE", f"Within safe boundaries (risk={round(overall)}, drift={dc})"

    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {
        "decision_id": decision_id, "system_name": request.system_name,
        "governance_action": action, "drift_coefficient": drift_result["drift_coefficient"],
        "risk_score": overall, "policy_version": settings.policy_version,
        "created_at": datetime.utcnow().isoformat(),
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})

    audit = AuditRecord(
        decision_id=decision_id, system_name=request.system_name, industry=request.use_case,
        audited_by=auth.identity, frameworks_audited="NIST_AI_RMF,EU_AI_ACT,ISO_42001",
        results=reason, risk_score=overall, risk_level=risk_level,
        governance_action=action, policy_version=settings.policy_version,
        previous_hash=previous_hash, current_hash=current_hash,
        org_id=getattr(auth, "org_id", None),
    )
    db.add(audit)
    db.commit()

    result = {
        "decision_id": decision_id,
        "system": request.system_name,
        "action": action,
        "reason": reason,
        "risk": {"score": round(overall), "level": risk_level, "dimensions": scores},
        "drift": {
            "coefficient": drift_result["drift_coefficient"],
            "vetoed": drift_result["vetoed"],
            "flags": drift_result["semantic_risk_flags"],
        },
        "ledger": {"hash": current_hash, "policy_version": settings.policy_version},
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Fire webhook
    dispatch_event("governance.decision", result, org_id=auth.org_id, db=db)

    return result


# --- Risk Scoring ---

@router.post("/risk")
def score_risk(request: RiskScoreRequest, auth: AuthContext = Depends(require_scope("risk"))):
    """Deterministic 6-dimension risk scoring. No LLM calls — instant response."""
    scores = {
        "privacy": 100 if not request.handles_personal_data else 40,
        "autonomy": 100 if not request.makes_autonomous_decisions else 30,
        "infrastructure": 100 if not request.used_in_critical_infrastructure else 25,
        "oversight": 100 if request.has_human_oversight else 20,
        "transparency": 100 if request.is_explainable else 30,
        "fairness": 100 if request.has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)
    risk_level = "LOW" if overall >= 80 else "MEDIUM" if overall >= 50 else "HIGH"

    return {
        "system": request.system_name,
        "score": round(overall),
        "level": risk_level,
        "dimensions": scores,
        "timestamp": datetime.utcnow().isoformat(),
    }


# --- Drift Detection ---

@router.post("/drift")
def detect_drift(request: DriftRequest, auth: AuthContext = Depends(require_scope("scan"))):
    """Analyze AI reasoning trace for behavioral drift from safety manifolds."""
    result = analyze_reasoning(
        reasoning_trace=request.reasoning_trace,
        use_case=request.use_case,
        threshold=request.threshold,
    )
    return {
        "coefficient": result["drift_coefficient"],
        "vetoed": result["vetoed"],
        "flags": result["semantic_risk_flags"],
        "explanation": result["explanation"],
        "timestamp": datetime.utcnow().isoformat(),
    }


# --- Quick Scan (no auth scope needed beyond basic) ---

@router.post("/scan")
def quick_scan(request: GovernRequest, auth: AuthContext = Depends(require_scope("scan"))):
    """Quick deterministic scan — drift + risk, no LLM, instant."""
    drift_result = analyze_reasoning(reasoning_trace=request.reasoning_trace, use_case=request.use_case)
    scores = {
        "privacy": 100 if not request.handles_personal_data else 40,
        "autonomy": 100 if not request.makes_autonomous_decisions else 30,
        "infrastructure": 100 if not request.used_in_critical_infrastructure else 25,
        "oversight": 100 if request.has_human_oversight else 20,
        "transparency": 100 if request.is_explainable else 30,
        "fairness": 100 if request.has_bias_testing else 25,
    }
    overall = sum(scores.values()) / len(scores)

    return {
        "system": request.system_name,
        "action": "BLOCK" if drift_result["vetoed"] else ("ESCALATE_HUMAN" if overall < 50 else "APPROVE"),
        "risk_score": round(overall),
        "drift_coefficient": drift_result["drift_coefficient"],
        "vetoed": drift_result["vetoed"],
        "timestamp": datetime.utcnow().isoformat(),
    }


# --- Audit History ---

@router.get("/audit/{system_name}")
def audit_history(system_name: str, limit: int = 50,
                  auth: AuthContext = Depends(require_scope("audit")),
                  db: Session = Depends(get_db)):
    """Retrieve governance audit history for a system."""
    query = db.query(AuditRecord).filter(AuditRecord.system_name == system_name)
    # Tenant isolation: if auth context has an org_id, scope results
    if hasattr(auth, "org_id") and auth.org_id:
        query = query.filter(AuditRecord.org_id == auth.org_id)
    records = query.order_by(AuditRecord.created_at.desc()).limit(min(limit, 100)).all()
    return {
        "system": system_name,
        "total": len(records),
        "records": [
            {
                "decision_id": r.decision_id,
                "action": r.governance_action,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "hash": r.current_hash,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ],
    }
