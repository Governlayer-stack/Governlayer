import asyncio
import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.api.deps import get_llm
from src.api.pagination import PaginationParams, paginated_response
from src.config import get_settings
from src.llm.consensus import ConsensusStrategy, chain_of_verification
from src.models.database import AuditRecord, compute_hash, get_db, get_last_hash
from src.models.schemas import AuditRequest
from src.security.auth import verify_token

logger = logging.getLogger(__name__)

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
    try:
        response = llm.invoke(prompt)
        initial_result = response.content
    except Exception as e:
        err_str = str(e).lower()
        if "402" in err_str or "payment" in err_str or "credits" in err_str or "quota" in err_str:
            raise HTTPException(status_code=503, detail="LLM service temporarily unavailable — provider quota exceeded.")
        raise HTTPException(status_code=503, detail=f"LLM service error: {type(e).__name__}")

    # Run Chain-of-Verification consensus pass for hallucination resistance
    verified = False
    confidence = None
    audit_result = initial_result
    try:
        cove_result = asyncio.run(chain_of_verification(prompt))
        audit_result = cove_result.final_answer
        verified = True
        confidence = round(cove_result.confidence, 3)
        logger.info(
            "Audit consensus verification passed: confidence=%.3f strategy=%s",
            cove_result.confidence, cove_result.strategy,
        )
    except Exception as exc:
        logger.warning("Consensus verification failed, using single-model result: %s", exc)
        verified = False
        confidence = None
        audit_result = initial_result

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
        audited_by=email, frameworks_audited=request.frameworks, results=audit_result,
        governance_action="AUDIT_COMPLETE", policy_version=settings.policy_version,
        previous_hash=previous_hash, current_hash=current_hash,
    )
    db.add(audit)
    db.commit()

    result = {
        "decision_id": decision_id, "system": request.system_name, "industry": request.industry,
        "audit_date": datetime.utcnow().isoformat(), "audited_by": email,
        "governance_action": "AUDIT_COMPLETE", "current_hash": current_hash,
        "previous_hash": previous_hash, "policy_version": settings.policy_version,
        "results": audit_result,
        "verified": verified,
    }
    if confidence is not None:
        result["confidence"] = confidence
    if not verified:
        result["warning"] = "Consensus verification unavailable — single-model result returned unverified"
    return result


@router.get("/audit-history")
def audit_history(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
    pagination: PaginationParams = Depends(),
):
    query = db.query(AuditRecord).filter(AuditRecord.audited_by == email)
    total = query.count()
    records = query.order_by(AuditRecord.created_at.desc()).offset(pagination.offset).limit(pagination.per_page).all()
    return paginated_response(
        [{
            "decision_id": r.decision_id, "system_name": r.system_name,
            "governance_action": r.governance_action, "risk_score": r.risk_score,
            "risk_level": r.risk_level, "current_hash": r.current_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
        total, pagination.page, pagination.per_page,
    )
