from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from src.models.database import get_db, AuditRecord, compute_hash
from src.security.auth import verify_token

router = APIRouter(tags=["ledger"])


@router.get("/ledger")
def view_ledger(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    total = db.query(AuditRecord).count()
    records = (
        db.query(AuditRecord)
        .order_by(AuditRecord.id.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "total_records": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total else 0,
        "ledger": [{
            "id": r.id, "decision_id": r.decision_id, "system_name": r.system_name,
            "governance_action": r.governance_action, "risk_score": r.risk_score,
            "risk_level": r.risk_level, "policy_version": r.policy_version,
            "previous_hash": r.previous_hash, "current_hash": r.current_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
    }


@router.get("/ledger/verify")
def verify_chain(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Verify the integrity of the hash-chained audit ledger."""
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    if not records:
        return {"valid": True, "total_records": 0, "message": "Empty ledger"}

    broken_links = []
    for i, record in enumerate(records):
        if i == 0:
            continue
        if record.previous_hash != records[i - 1].current_hash:
            broken_links.append({
                "record_id": record.id,
                "decision_id": record.decision_id,
                "expected_previous": records[i - 1].current_hash,
                "actual_previous": record.previous_hash,
            })

    return {
        "valid": len(broken_links) == 0,
        "total_records": len(records),
        "broken_links": broken_links,
    }
