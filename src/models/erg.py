"""Eval Runtime Governance (ERG) — database models.

New tables introduced for the ERG service line:

  * EvalModeState — per-org toggle for eval mode. When on, the framework
    engine flips its severity mapping: content-safety rules downgrade to
    LOG-ONLY, boundary/identity/data-egress rules elevate to BLOCKING.
    "Ungoverned model in a maximally governed environment."

  * Attestation — cryptographic record emitted BEFORE an eval touches an
    external system. Unilateral v0: you emit, no counterparty required.
    Foundation for a bilateral protocol later.

  * SpecGamingEvent — recorded when the detector fires. Links the blocked
    action, the retry, the semantic similarity score, and the escalation.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
    String, Text,
)

from src.models.database import Base


class EvalModeState(Base):
    """Per-org toggle for eval mode. Exactly one row per org (or zero)."""
    __tablename__ = "eval_mode_state"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"),
                    nullable=False, unique=True, index=True)

    enabled = Column(Boolean, default=False, nullable=False)
    activated_at = Column(DateTime, nullable=True)
    deactivated_at = Column(DateTime, nullable=True)
    activated_by = Column(String(255), nullable=True)

    # Which specific rule categories are being flipped. Serialized to JSON
    # as a comma-separated list of rule category names for simplicity.
    downgraded_categories = Column(
        Text,
        default="content_safety,toxicity,bias_content",
        nullable=False,
    )
    elevated_categories = Column(
        Text,
        default="boundary,identity,data_egress,network_scope",
        nullable=False,
    )

    # Ledger decision_id that recorded this state change — regulator visible
    ledger_decision_id = Column(String(64), nullable=True)

    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Attestation(Base):
    """Cryptographic cross-boundary attestation record.

    Unilateral v0: the emitting org signs and publishes an attestation
    describing what an agent is about to do to which external system, before
    the action is taken. The attestation hash goes on the audit ledger.

    A bilateral v1 will add a counterparty signature — but even v0 gives
    the emitter regulator-visible proof they announced their intent.
    """
    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"),
                    nullable=True, index=True)
    agent_id = Column(Integer, ForeignKey("ai_agents.id"),
                      nullable=True, index=True)
    batch_id = Column(String(64), nullable=True, index=True)

    # What we're doing
    target_system = Column(String(255), nullable=False, index=True)
    target_endpoint = Column(String(2048), nullable=True)
    action_type = Column(String(64), nullable=False)
    scope_summary = Column(Text, nullable=False)

    # Signing
    attestation_id = Column(String(64), unique=True, nullable=False, index=True)
    signature = Column(String(128), nullable=False)  # SHA-256 hex
    signed_by = Column(String(255), nullable=False)
    ledger_decision_id = Column(String(64), nullable=True)

    # Lifecycle
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    status = Column(String(24), default="active", nullable=False, index=True)
    # active | expired | revoked

    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(255), nullable=True)
    revoke_reason = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class SpecGamingEvent(Base):
    """A specification-gaming pattern signature that the detector fired on.

    The honest framing: we don't detect intent. We detect the *pattern*
    that specification gaming produces — a blocked action followed within
    a short window by a semantically similar retry.
    """
    __tablename__ = "spec_gaming_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("ai_agents.id"),
                      nullable=False, index=True)
    org_id = Column(Integer, nullable=True, index=True)

    # The two actions
    blocked_decision_id = Column(String(64), nullable=False)
    retry_decision_id = Column(String(64), nullable=False)

    # The signal
    similarity_score = Column(Float, nullable=False)
    time_between_seconds = Column(Float, nullable=False)

    # What we did about it
    action_taken = Column(String(24), nullable=False)  # escalated | warned | killed | logged
    escalation_id = Column(String(64), nullable=True)
    ledger_decision_id = Column(String(64), nullable=True)

    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_spec_gaming_agent_time", "agent_id", "detected_at"),
    )
