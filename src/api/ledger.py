from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.models.database import get_db, AuditRecord
from src.security.auth import verify_token

router = APIRouter(tags=["ledger"])


@router.get("/ledger")
def view_ledger(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    return {
        "total_records": len(records),
        "ledger": [{
            "id": r.id, "decision_id": r.decision_id, "system_name": r.system_name,
            "governance_action": r.governance_action, "risk_score": r.risk_score,
            "risk_level": r.risk_level, "policy_version": r.policy_version,
            "previous_hash": r.previous_hash, "current_hash": r.current_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
    }
