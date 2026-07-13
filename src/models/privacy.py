"""GDPR / CCPA privacy request models.

Two operations covered:

  * DSAR — Data Subject Access Request (GDPR Article 15, CCPA §1798.100):
    the subject asks to see everything we hold about them. We must respond
    within the regulatory window (30 days GDPR, 45 days CCPA).

  * DELETION — Right to Erasure (GDPR Article 17, CCPA §1798.105):
    the subject asks us to delete their data. We must cascade across
    every downstream store, not just the primary user row.

Every request lands as a `PrivacyRequest`. Fulfillment is recorded on the
row plus emitted to the audit ledger for regulator-facing evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text

from src.models.database import Base


class PrivacyRequest(Base):
    __tablename__ = "privacy_requests"

    id = Column(Integer, primary_key=True, index=True)
    request_type = Column(String(16), nullable=False, index=True)  # "dsar" | "deletion"
    subject_email = Column(String(255), nullable=False, index=True)
    status = Column(String(24), default="pending", nullable=False, index=True)
    # pending | in_progress | completed | rejected

    # Statutory window: 30 days GDPR, 45 days CCPA. We store both so we can
    # report against whichever regime applies.
    submitted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    due_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    requester = Column(String(255), nullable=True)  # who submitted (may be same as subject)
    verification_method = Column(String(64), nullable=True)  # "email_link" | "identity_doc" | "operator"
    verification_notes = Column(Text, nullable=True)

    # Fulfillment record
    records_disclosed = Column(Integer, default=0, nullable=False)
    records_deleted = Column(Integer, default=0, nullable=False)
    records_anonymized = Column(Integer, default=0, nullable=False)
    downstream_stores_cleared = Column(Text, nullable=True)  # comma-separated names
    ledger_decision_id = Column(String(64), nullable=True)   # links to hash-chained record

    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
