"""Evidence collection database models.

Tables:
- evidence_connectors: configured integrations with encrypted config
- evidence_items: collected compliance evidence mapped to controls
- evidence_schedules: automated collection schedules
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from src.models.database import Base


class EvidenceConnectorDB(Base):
    """Persisted connector configuration."""

    __tablename__ = "evidence_connectors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    connector_type = Column(String(50), nullable=False)  # aws, github, rest, ...
    config_encrypted = Column(Text, nullable=True)  # JSON config (should be encrypted at rest)
    status = Column(String(50), default="available", nullable=False)  # available, connected, error
    last_collected_at = Column(DateTime, nullable=True)
    created_by = Column(String(255), nullable=False)
    org_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    items = relationship("EvidenceItemDB", back_populates="connector", cascade="all, delete-orphan")
    schedules = relationship("EvidenceScheduleDB", back_populates="connector", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_evidence_connectors_org_type", "org_id", "connector_type"),
    )


class EvidenceItemDB(Base):
    """A single piece of collected compliance evidence."""

    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(Integer, ForeignKey("evidence_connectors.id"), nullable=False, index=True)
    control_id = Column(String(100), nullable=True, index=True)  # e.g. SOC2-CC6.1
    framework = Column(String(100), nullable=True)  # e.g. SOC2, ISO27001
    evidence_type = Column(String(100), nullable=False)  # e.g. branch_protection, iam_policies
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=True)  # JSON blob of raw evidence data
    source = Column(String(500), nullable=True)  # e.g. github:repos, aws:cloudtrail
    status = Column(String(50), default="collected", nullable=False)  # collected, verified, stale, failed
    collected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    mapped_controls = Column(Text, nullable=True)  # JSON array of control IDs

    connector = relationship("EvidenceConnectorDB", back_populates="items")

    __table_args__ = (
        Index("ix_evidence_items_framework_control", "framework", "control_id"),
        Index("ix_evidence_items_collected", "collected_at"),
    )


class EvidenceScheduleDB(Base):
    """Automated collection schedule for a connector."""

    __tablename__ = "evidence_schedules"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(Integer, ForeignKey("evidence_connectors.id"), nullable=False, index=True)
    cron_expression = Column(String(100), nullable=False)  # e.g. "0 * * * *" for hourly
    enabled = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    connector = relationship("EvidenceConnectorDB", back_populates="schedules")
