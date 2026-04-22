"""Model Registry and Incident Management database models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import relationship
import enum

from src.models.database import Base


class ModelLifecycle(str, enum.Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class RegisteredModel(Base):
    __tablename__ = "registered_models"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    provider = Column(String(100))
    model_type = Column(String(100))
    lifecycle = Column(SAEnum(ModelLifecycle), default=ModelLifecycle.DEVELOPMENT)
    risk_tier = Column(String(50))
    description = Column(Text)
    owner = Column(String(255))
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    governance_status = Column(String(50), default="pending")
    last_audit_at = Column(DateTime)
    risk_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cards = relationship("ModelCard", back_populates="model", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="model", cascade="all, delete-orphan")


class ModelCard(Base):
    __tablename__ = "model_cards"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("registered_models.id"), nullable=False)
    intended_use = Column(Text)
    limitations = Column(Text)
    training_data_summary = Column(Text)
    evaluation_metrics = Column(JSON, default=dict)
    ethical_considerations = Column(Text)
    fairness_analysis = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    model = relationship("RegisteredModel", back_populates="cards")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    model_id = Column(Integer, ForeignKey("registered_models.id"), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SAEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM)
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN)
    category = Column(String(100))
    root_cause = Column(Text)
    resolution = Column(Text)
    impact = Column(Text)
    reporter = Column(String(255))
    assignee = Column(String(255))
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)

    model = relationship("RegisteredModel", back_populates="incidents")
