"""AI Agent Registry and Shadow AI Discovery database models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, JSON, Boolean, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import relationship
import enum

from src.models.database import Base


class AgentType(str, enum.Enum):
    AUTONOMOUS = "autonomous"
    SEMI_AUTONOMOUS = "semi_autonomous"
    SUPERVISED = "supervised"
    TOOL_AGENT = "tool_agent"
    WORKFLOW = "workflow"
    CHATBOT = "chatbot"


class AgentStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    # Terminal state: agent was killed via /agent-registry/agents/{id}/kill.
    # Required by SR 26-2 §V.3 (kill-switch capability). Once KILLED the
    # agent cannot be re-approved without registering a new agent record.
    KILLED = "killed"
    # ERG four-tier circuit breaker:
    #   WARNED — a soft signal was raised (e.g. approaching a budget cap or
    #   a spec-gaming pattern was detected). Agent still runs; operator
    #   should review before it escalates further.
    WARNED = "warned"
    #   LOCKED_DOWN — the agent AND every sibling agent sharing the same
    #   batch_id have been killed atomically. Terminal; used when an eval
    #   batch demonstrates coordinated boundary probing.
    LOCKED_DOWN = "locked_down"


class DiscoverySource(str, enum.Enum):
    MANUAL = "manual"
    API_SCAN = "api_scan"
    LOG_ANALYSIS = "log_analysis"
    NETWORK_SCAN = "network_scan"
    REGISTRY_SYNC = "registry_sync"


class AIAgent(Base):
    __tablename__ = "ai_agents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    agent_type = Column(SAEnum(AgentType), default=AgentType.AUTONOMOUS)
    status = Column(SAEnum(AgentStatus), default=AgentStatus.UNDER_REVIEW)
    description = Column(Text)
    owner = Column(String(255))
    team = Column(String(255))
    purpose = Column(Text)
    tools = Column(JSON, default=list)
    data_sources = Column(JSON, default=list)
    permissions = Column(JSON, default=list)
    guardrails = Column(JSON, default=list)
    autonomy_level = Column(Integer, default=1)
    model_provider = Column(String(100))
    model_name = Column(String(255))
    model_id = Column(Integer, ForeignKey("registered_models.id"), nullable=True)
    risk_tier = Column(String(50))
    risk_score = Column(Float)
    governance_status = Column(String(50), default="pending")
    last_audit_at = Column(DateTime)
    approved_by = Column(String(255))
    approved_at = Column(DateTime)
    dependencies = Column(JSON, default=list)
    upstream_services = Column(JSON, default=list)
    downstream_services = Column(JSON, default=list)
    discovery_source = Column(SAEnum(DiscoverySource), default=DiscoverySource.MANUAL)
    is_shadow = Column(Boolean, default=False)
    first_seen_at = Column(DateTime)
    last_activity_at = Column(DateTime)
    # ERG: agents sharing the same batch_id are treated as a coordinated
    # unit for lockdown purposes — kill one, lock down all.
    batch_id = Column(String(64), nullable=True, index=True)
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    card = relationship("AgentCard", back_populates="agent", uselist=False, cascade="all, delete-orphan")


class AgentCard(Base):
    __tablename__ = "agent_cards"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("ai_agents.id"), nullable=False, unique=True)
    intended_use = Column(Text)
    limitations = Column(Text)
    ethical_considerations = Column(Text)
    interaction_patterns = Column(JSON, default=list)
    failure_modes = Column(JSON, default=list)
    escalation_policy = Column(Text)
    data_retention = Column(Text)
    compliance_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = relationship("AIAgent", back_populates="card")


class ShadowAIDetection(Base):
    __tablename__ = "shadow_ai_detections"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    detection_type = Column(String(100), nullable=False)
    source = Column(String(255))
    description = Column(Text)
    evidence = Column(JSON, default=dict)
    severity = Column(String(20), default="medium")
    status = Column(String(20), default="new")
    detected_service = Column(String(255))
    detected_model = Column(String(255))
    detected_by = Column(String(255))
    agent_id = Column(Integer, ForeignKey("ai_agents.id"), nullable=True)
    remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentBudget(Base):
    """Enforced autonomy budget per agent (SR 26-2 §V.3 companion to kill switch).

    Budgets enforce hard limits *in the runtime*, not in the prompt. When an
    agent exhausts any budget dimension, the platform auto-kills it and
    records the exhaustion on the audit ledger.

    A budget can be:
      * one-shot (`period="total"`): budget never resets, exhaustion = terminal.
      * time-windowed (`period="hourly"|"daily"`): resets at the start of each
        window; used_steps and used_spend_usd zero out.
    """
    __tablename__ = "agent_budgets"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("ai_agents.id"), nullable=False, unique=True, index=True)

    # Hard caps
    step_budget = Column(Integer, nullable=True)          # None = no cap
    spend_budget_usd = Column(Float, nullable=True)       # None = no cap
    recursion_depth_limit = Column(Integer, nullable=True)  # None = no cap

    # Consumed
    used_steps = Column(Integer, default=0, nullable=False)
    used_spend_usd = Column(Float, default=0.0, nullable=False)

    # Window
    period = Column(String(16), default="total", nullable=False)  # "total" | "hourly" | "daily"
    period_start = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Enforcement action once exhausted: "kill" or "pause"
    on_exhaustion = Column(String(16), default="kill", nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
