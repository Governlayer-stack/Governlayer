import csv
import io
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from src.api.pagination import PaginationParams, paginated_response
from src.models.database import AuditRecord, get_db
from src.security.auth import verify_token

router = APIRouter(tags=["ledger"])

EXPORT_FIELDS = [
    "decision_id", "system_name", "industry", "audited_by",
    "frameworks_audited", "risk_score", "risk_level", "governance_action",
    "policy_version", "current_hash", "previous_hash", "created_at",
]


def _record_to_dict(r: AuditRecord) -> dict:
    return {
        "decision_id": r.decision_id,
        "system_name": r.system_name,
        "industry": r.industry,
        "audited_by": r.audited_by,
        "frameworks_audited": r.frameworks_audited,
        "risk_score": r.risk_score,
        "risk_level": r.risk_level,
        "governance_action": r.governance_action,
        "policy_version": r.policy_version,
        "current_hash": r.current_hash,
        "previous_hash": r.previous_hash,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("/ledger")
def view_ledger(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
    pagination: PaginationParams = Depends(),
):
    total = db.query(AuditRecord).count()
    records = (
        db.query(AuditRecord)
        .order_by(AuditRecord.id.asc())
        .offset(pagination.offset)
        .limit(pagination.per_page)
        .all()
    )
    return paginated_response(
        [{
            "id": r.id, "decision_id": r.decision_id, "system_name": r.system_name,
            "governance_action": r.governance_action, "risk_score": r.risk_score,
            "risk_level": r.risk_level, "policy_version": r.policy_version,
            "previous_hash": r.previous_hash, "current_hash": r.current_hash,
            "created_at": r.created_at.isoformat(),
        } for r in records],
        total, pagination.page, pagination.per_page,
    )


@router.get("/ledger/export")
def export_ledger(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
    format: str = Query("json", pattern="^(json|csv)$"),
    from_date: Optional[datetime] = Query(None, description="Filter records from this date (ISO 8601)"),
    to_date: Optional[datetime] = Query(None, description="Filter records up to this date (ISO 8601)"),
    system_name: Optional[str] = Query(None, description="Filter by system name"),
    limit: int = Query(10000, ge=1, le=10000),
):
    """Export audit trail as JSON or CSV with optional filters."""
    query = db.query(AuditRecord).order_by(AuditRecord.id.asc())

    if from_date is not None:
        query = query.filter(AuditRecord.created_at >= from_date)
    if to_date is not None:
        query = query.filter(AuditRecord.created_at <= to_date)
    if system_name is not None:
        query = query.filter(AuditRecord.system_name == system_name)

    records = query.limit(limit).all()
    rows = [_record_to_dict(r) for r in records]

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        csv_content = output.getvalue()
        output.close()

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=governlayer_audit_export.csv",
            },
        )

    return {"total": len(rows), "records": rows}


@router.get("/ledger/verify")
def verify_chain(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Verify the integrity of the hash-chained audit ledger."""
    records = db.query(AuditRecord).order_by(AuditRecord.id.asc()).all()
    if not records:
        return {"valid": True, "records_checked": 0, "first_broken_at": None}

    for i in range(1, len(records)):
        if records[i].previous_hash != records[i - 1].current_hash:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_at": records[i].decision_id,
            }

    return {
        "valid": True,
        "records_checked": len(records),
        "first_broken_at": None,
    }
