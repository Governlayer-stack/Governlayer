from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime
import uuid

from src.models.database import get_db, AuditRecord, compute_hash, get_last_hash
from src.models.schemas import AuditRequest
from src.security.auth import verify_token
from src.api.deps import get_llm
from src.config import get_settings

router = APIRouter(tags=["audit"])
settings = get_settings()


@router.post("/audit")
def audit_system(request: AuditRequest, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    llm = get_llm()
    prompt = (
        f"You are a world class AI governance auditor. Audit this system: {request.system_name} "
        f"in {request.industry}. Description: {request.system_description}. "
        f"Frameworks: {request.frameworks}. For each framework provide compliance status, gaps and recommendations."
    )
    response = llm.invoke(prompt)

    decision_id = str(uuid.uuid4())
    previous_hash = get_last_hash(db)
    record_data = {
        "decision_id": decision_id, "system_name": request.system_name,
        "governance_action": "AUDIT_COMPLETE", "policy_version": settings.policy_version,
        "created_at": datetime.utcnow().isoformat(),
    }
    current_hash = compute_hash({**record_data, "previous_hash": previous_hash})

    audit = AuditRecord(
        decision_id=decision_id, system_name=request.system_name, industry=request.industry,
        audited_by=email, frameworks_audited=request.frameworks, results=response.content,
        governance_action="AUDIT_COMPLETE", policy_version=settings.policy_version,
        previous_hash=previous_hash, current_hash=current_hash,
    )
    db.add(audit)
    db.commit()

    return {
        "decision_id": decision_id, "system": request.system_name, "industry": request.industry,
        "audit_date": datetime.utcnow().isoformat(), "audited_by": email,
        "governance_action": "AUDIT_COMPLETE", "current_hash": current_hash,
        "previous_hash": previous_hash, "policy_version": settings.policy_version,
        "results": response.content,
    }


@router.get("/audit-history")
def audit_history(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    query = db.query(AuditRecord).filter(AuditRecord.audited_by == email)
    total = query.count()
    records = query.order_by(AuditRecord.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total else 0,
        "audits": [{
            "decision_id": r.decision_id, "system_name": r.system_name,
            "governance_action": r.governance_action, "risk_score": r.risk_score,
            "risk_level": r.risk_level, "current_hash": r.current_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
    }
