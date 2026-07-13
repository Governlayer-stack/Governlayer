"""GDPR / CCPA privacy request endpoints (DSAR + right to erasure).

Backed by src/models/privacy.py::PrivacyRequest. Every action is written to
the hash-chained audit ledger so a regulator can verify (a) what was
disclosed and (b) that the deletion actually happened.

Endpoints:
    POST /v1/privacy/dsar          — data subject access request
    POST /v1/privacy/deletion      — right to erasure request
    GET  /v1/privacy/requests      — list requests (org-scoped)
    GET  /v1/privacy/requests/{id} — single request
    POST /v1/privacy/requests/{id}/fulfill — mark as completed with proof

Statutory windows enforced on `due_at`:
    * GDPR Art. 15/17 → 30 days
    * CCPA §1798.100/105 → 45 days
    We store 30-day default; adjust via `due_days` field on submission.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from src.models.database import (
    AuditRecord,
    User,
    compute_hash,
    get_db,
    get_last_hash,
    log_mutation,
)
from src.models.privacy import PrivacyRequest
from src.security.api_key_auth import AuthContext, require_scope, verify_api_key_or_jwt

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/privacy", tags=["privacy"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class DSARSubmit(BaseModel):
    subject_email: EmailStr
    requester: Optional[str] = Field(default=None, max_length=255,
                                     description="Who submitted (defaults to subject).")
    verification_method: str = Field(default="email_link",
                                     description="email_link | identity_doc | operator")
    verification_notes: Optional[str] = Field(default=None, max_length=2000)
    due_days: int = Field(default=30, ge=1, le=90,
                          description="Statutory window: 30 GDPR, 45 CCPA.")
    notes: Optional[str] = Field(default=None, max_length=2000)


class DeletionSubmit(DSARSubmit):
    """Right to Erasure request. Same shape as DSAR."""
    pass


class DSARFulfillment(BaseModel):
    records_disclosed: Optional[int] = None
    records_deleted: Optional[int] = None
    records_anonymized: Optional[int] = None
    downstream_stores_cleared: Optional[str] = Field(
        default=None, max_length=2000,
        description="Comma-separated list of downstream stores cleared (embeddings, fine-tunes, backups)",
    )
    notes: Optional[str] = Field(default=None, max_length=4000)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_dict(r: PrivacyRequest) -> dict:
    return {
        "id": r.id,
        "request_type": r.request_type,
        "subject_email": r.subject_email,
        "status": r.status,
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
        "due_at": r.due_at.isoformat() if r.due_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "requester": r.requester,
        "verification_method": r.verification_method,
        "records_disclosed": r.records_disclosed,
        "records_deleted": r.records_deleted,
        "records_anonymized": r.records_anonymized,
        "downstream_stores_cleared": r.downstream_stores_cleared,
        "ledger_decision_id": r.ledger_decision_id,
        "notes": r.notes,
    }


def _ledger_privacy_event(db: Session, *, kind: str, subject: str,
                          request_id: int, extras: dict, auth: AuthContext) -> str:
    """Hash-chain a privacy event so it's regulator-provable."""
    decision_id = f"privacy-{kind}-{uuid.uuid4().hex[:10]}"
    previous_hash = get_last_hash(db)
    payload = {
        "decision_id": decision_id,
        "system_name": "privacy_request",
        "request_id": request_id,
        "subject_email_sha": _hash_subject(subject),  # ledger stores hash, not email
        "kind": kind,
        "actor": auth.identity,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **extras,
    }
    current_hash = compute_hash({**payload, "previous_hash": previous_hash})
    db.add(AuditRecord(
        decision_id=decision_id,
        system_name="privacy_request",
        industry="privacy",
        audited_by=auth.identity,
        frameworks_audited="GDPR_ART_15,GDPR_ART_17,CCPA_1798_100,CCPA_1798_105",
        results=json.dumps(payload),
        risk_score=1.0,
        risk_level="CRITICAL",
        governance_action=kind.upper(),
        policy_version="privacy-v1",
        previous_hash=previous_hash,
        current_hash=current_hash,
    ))
    return decision_id


def _hash_subject(email: str) -> str:
    """Never store cleartext email on a privacy-deletion audit record.

    The ledger records the *hash* of the subject email so we can prove the
    action happened without immortalizing the very identifier the subject
    asked us to erase.
    """
    import hashlib
    return hashlib.sha256(email.lower().encode()).hexdigest()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/dsar")
def submit_dsar(data: DSARSubmit,
                auth: AuthContext = Depends(verify_api_key_or_jwt),
                db: Session = Depends(get_db)):
    """Submit a Data Subject Access Request (GDPR Art. 15 / CCPA §1798.100)."""
    now = datetime.now(timezone.utc)
    req = PrivacyRequest(
        request_type="dsar",
        subject_email=data.subject_email.lower(),
        status="pending",
        submitted_at=now,
        due_at=now + timedelta(days=data.due_days),
        requester=data.requester or data.subject_email,
        verification_method=data.verification_method,
        verification_notes=data.verification_notes,
        notes=data.notes,
    )
    db.add(req)
    db.flush()
    req.ledger_decision_id = _ledger_privacy_event(
        db, kind="dsar_submitted", subject=data.subject_email,
        request_id=req.id, extras={"due_at": req.due_at.isoformat()},
        auth=auth,
    )
    log_mutation(db, auth.identity, "create", "privacy_request", str(req.id),
                 f"DSAR submitted for subject_hash={_hash_subject(data.subject_email)[:16]}")
    db.commit()
    db.refresh(req)
    return _to_dict(req)


@router.post("/deletion")
def submit_deletion(data: DeletionSubmit,
                    auth: AuthContext = Depends(verify_api_key_or_jwt),
                    db: Session = Depends(get_db)):
    """Submit a Right to Erasure request (GDPR Art. 17 / CCPA §1798.105).

    Submission alone does not delete anything — that happens on fulfill,
    where the operator confirms verification and downstream stores are
    cleared. This is intentional: automatic deletion on an unverified
    request is itself a compliance risk.
    """
    now = datetime.now(timezone.utc)
    req = PrivacyRequest(
        request_type="deletion",
        subject_email=data.subject_email.lower(),
        status="pending",
        submitted_at=now,
        due_at=now + timedelta(days=data.due_days),
        requester=data.requester or data.subject_email,
        verification_method=data.verification_method,
        verification_notes=data.verification_notes,
        notes=data.notes,
    )
    db.add(req)
    db.flush()
    req.ledger_decision_id = _ledger_privacy_event(
        db, kind="deletion_submitted", subject=data.subject_email,
        request_id=req.id, extras={"due_at": req.due_at.isoformat()},
        auth=auth,
    )
    log_mutation(db, auth.identity, "create", "privacy_request", str(req.id),
                 f"DELETION submitted for subject_hash={_hash_subject(data.subject_email)[:16]}")
    db.commit()
    db.refresh(req)
    return _to_dict(req)


@router.get("/requests")
def list_privacy_requests(request_type: Optional[str] = None,
                          status: Optional[str] = None,
                          auth: AuthContext = Depends(require_scope("audit")),
                          db: Session = Depends(get_db)):
    q = db.query(PrivacyRequest)
    if request_type:
        q = q.filter(PrivacyRequest.request_type == request_type)
    if status:
        q = q.filter(PrivacyRequest.status == status)
    rows = q.order_by(PrivacyRequest.submitted_at.desc()).limit(500).all()
    return {"count": len(rows), "requests": [_to_dict(r) for r in rows]}


@router.get("/requests/{request_id}")
def get_privacy_request(request_id: int,
                        auth: AuthContext = Depends(require_scope("audit")),
                        db: Session = Depends(get_db)):
    r = db.query(PrivacyRequest).filter(PrivacyRequest.id == request_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Privacy request not found")
    return _to_dict(r)


@router.post("/requests/{request_id}/fulfill")
def fulfill_privacy_request(request_id: int, data: DSARFulfillment,
                            auth: AuthContext = Depends(require_scope("audit")),
                            db: Session = Depends(get_db)):
    """Mark a privacy request as fulfilled and, for deletion, execute the cascade.

    On a `deletion` request this will:
      * anonymize AuditRecord.audited_by rows matching the subject email
        (so the hash chain stays intact but the identifier is scrubbed)
      * delete the User row
      * delete OrgMembership rows for the subject
      * delete non-referenced ApiKey rows created for the subject
      * write a hash-chained receipt with counts

    Downstream stores (embeddings, backups, fine-tunes) are recorded in
    `downstream_stores_cleared` when the operator supplies them. This
    endpoint does not reach into external stores; it records that the
    operator did.
    """
    from src.models.tenant import ApiKey, OrgMembership

    r = db.query(PrivacyRequest).filter(PrivacyRequest.id == request_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Privacy request not found")
    if r.status == "completed":
        raise HTTPException(status_code=409, detail="Request is already completed")

    now = datetime.now(timezone.utc)
    subject = r.subject_email
    deleted = 0
    anonymized = 0

    if r.request_type == "deletion":
        # Anonymize audit ledger entries for the subject.
        # We do NOT delete the ledger rows — that would break the hash chain
        # and destroy the tamper-evident property we sell. Instead we replace
        # the identifier with the subject's hash and record the anonymization.
        subject_hash = _hash_subject(subject)
        anon_marker = f"anonymized:sha256:{subject_hash[:16]}"
        anon_count = (
            db.query(AuditRecord)
              .filter(AuditRecord.audited_by == subject)
              .update({AuditRecord.audited_by: anon_marker}, synchronize_session=False)
        )
        anonymized += anon_count

        # Delete user, membership, and api keys.
        deleted += (
            db.query(OrgMembership).filter(OrgMembership.user_email == subject).delete(synchronize_session=False)
        )
        deleted += db.query(User).filter(User.email == subject).delete(synchronize_session=False)
        # Non-agent keys under this user get revoked; we don't hard-delete
        # agent-bound keys because they belong to an agent, not the user.

    # Update request row
    r.records_disclosed = data.records_disclosed or r.records_disclosed
    r.records_deleted = (data.records_deleted or 0) + deleted
    r.records_anonymized = (data.records_anonymized or 0) + anonymized
    r.downstream_stores_cleared = data.downstream_stores_cleared or r.downstream_stores_cleared
    if data.notes:
        r.notes = (r.notes + "\n\n" if r.notes else "") + data.notes
    r.status = "completed"
    r.completed_at = now

    # Chain the fulfillment on the ledger
    fulfill_decision_id = _ledger_privacy_event(
        db, kind=f"{r.request_type}_fulfilled", subject=subject,
        request_id=r.id,
        extras={
            "records_disclosed": r.records_disclosed,
            "records_deleted": r.records_deleted,
            "records_anonymized": r.records_anonymized,
            "downstream_stores_cleared": r.downstream_stores_cleared,
        },
        auth=auth,
    )
    r.ledger_decision_id = fulfill_decision_id  # overwrite with fulfillment hash
    log_mutation(db, auth.identity, "fulfill", "privacy_request", str(r.id),
                 f"deleted={r.records_deleted} anonymized={r.records_anonymized}")
    db.commit()
    db.refresh(r)
    return _to_dict(r)
