"""SQLAlchemy models for the Compliance Hub — programs, policies, audits."""

from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from src.models.database import Base


class ComplianceProgram(Base):
    __tablename__ = "compliance_programs"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    frameworks = Column(Text, nullable=False)  # JSON list of framework IDs
    owner = Column(String(255), nullable=False)
    start_date = Column(String(10), nullable=False)
    target_audit_date = Column(String(10), nullable=False)
    controls = Column(Text, nullable=False)  # JSON list of control dicts
    created_at = Column(String(30), nullable=False)
    org_id = Column(Integer, nullable=True, index=True)

    policies = relationship("CompliancePolicy", back_populates="program", cascade="all, delete-orphan")
    audits = relationship("ComplianceAudit", back_populates="program", cascade="all, delete-orphan")


class CompliancePolicy(Base):
    __tablename__ = "compliance_policies"

    id = Column(String(64), primary_key=True, index=True)
    program_id = Column(String(64), ForeignKey("compliance_programs.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)
    sections = Column(Text, nullable=True)  # JSON list of section names
    applicable_frameworks = Column(Text, nullable=True)  # JSON list
    status = Column(String(20), nullable=False, default="draft")
    version = Column(String(20), nullable=False, default="1.0")
    word_count = Column(Integer, nullable=True)
    generated_by = Column(String(255), nullable=True)
    generated_at = Column(String(30), nullable=True)
    last_modified_by = Column(String(255), nullable=True)

    program = relationship("ComplianceProgram", back_populates="policies")


class ComplianceAudit(Base):
    __tablename__ = "compliance_audits"

    id = Column(String(64), primary_key=True, index=True)
    program_id = Column(String(64), ForeignKey("compliance_programs.id"), nullable=False, index=True)
    auditor_firm = Column(String(255), nullable=False)
    proposed_date = Column(String(10), nullable=False)
    audit_type = Column(String(20), nullable=False)
    notes = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="scheduled")
    readiness_at_scheduling = Column(Float, nullable=True)
    scheduled_by = Column(String(255), nullable=True)
    scheduled_at = Column(String(30), nullable=True)

    program = relationship("ComplianceProgram", back_populates="audits")
