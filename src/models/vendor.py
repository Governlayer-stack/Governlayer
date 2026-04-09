"""SQLAlchemy models for Vendor Risk Management."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from src.models.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _new_uuid():
    return str(uuid.uuid4())


class Vendor(Base):
    """A third-party vendor tracked for risk assessment."""

    __tablename__ = "vendors"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    name = Column(String(255), nullable=False, index=True)
    category = Column(String(50), nullable=False, default="ai_platform")
    services = Column(Text, nullable=True)  # JSON list
    data_shared = Column(Text, nullable=True)  # JSON list
    ai_usage = Column(String(1000), nullable=True, default="none")
    compliance_certifications = Column(Text, nullable=True)  # JSON list
    contract_end_date = Column(DateTime, nullable=True)
    contact_email = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    questionnaire_status = Column(String(50), nullable=False, default="not_sent")

    # Cached latest assessment results (denormalized for fast reads)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    risk_details = Column(Text, nullable=True)  # JSON with all 5 dimension scores

    last_assessed = Column(DateTime, nullable=True)
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    assessments = relationship(
        "VendorAssessment", back_populates="vendor", cascade="all, delete-orphan",
        order_by="VendorAssessment.assessed_at.desc()",
    )


class VendorAssessment(Base):
    """A point-in-time risk assessment of a vendor."""

    __tablename__ = "vendor_assessments"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    vendor_id = Column(String(36), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_type = Column(String(50), nullable=False, default="deterministic")
    scores = Column(Text, nullable=False)  # JSON: the 5 dimension scores
    overall_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    assessed_by = Column(String(255), nullable=False)
    assessed_at = Column(DateTime, nullable=False, default=_utcnow)

    vendor = relationship("Vendor", back_populates="assessments")
