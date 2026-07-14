"""Webhook delivery records for observability and retry.

A row per delivery attempt. Never mutated after write — we insert a fresh
row on each retry so an operator can see the full history of a given
event's fan-out. Rows are pruned by a lightweight cleanup query, not by
the dispatcher itself.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, Integer, String, Text

from src.models.database import Base


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"

    id = Column(Integer, primary_key=True, index=True)
    webhook_id = Column(Integer, ForeignKey("webhooks.id"), nullable=True, index=True)
    org_id = Column(Integer, nullable=True, index=True)

    event_type = Column(String(64), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    payload_preview = Column(Text, nullable=True)  # first 1KB of the JSON body

    # Attempt tracking
    attempt = Column(Integer, default=1, nullable=False)
    status = Column(String(24), default="queued", nullable=False, index=True)
    # queued | delivered | failed_retryable | failed_terminal

    response_status_code = Column(Integer, nullable=True)
    response_body_preview = Column(Text, nullable=True)  # first 1KB
    latency_ms = Column(Float, nullable=True)
    error = Column(Text, nullable=True)

    # Retry policy
    next_retry_at = Column(DateTime, nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_webhook_deliveries_status_next_retry", "status", "next_retry_at"),
    )
