"""Add webhook_deliveries table for P2 async webhook queue.

Revision ID: k1f2g3h4i5j6
Revises: j0e1f2g3h4i5
Create Date: 2026-07-14 12:00:00.000000

Adds the WebhookDelivery table so every webhook dispatch has a durable
row that survives process crashes, exposes retry state via
GET /webhooks/deliveries, and drives the background sweeper.
"""

from alembic import op
import sqlalchemy as sa

revision = "k1f2g3h4i5j6"
down_revision = "j0e1f2g3h4i5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("webhook_id", sa.Integer(), sa.ForeignKey("webhooks.id"), nullable=True),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("payload_preview", sa.Text(), nullable=True),
        sa.Column("attempt", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(24), server_default="queued", nullable=False),
        sa.Column("response_status_code", sa.Integer(), nullable=True),
        sa.Column("response_body_preview", sa.Text(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_webhook_deliveries_webhook_id", "webhook_deliveries", ["webhook_id"])
    op.create_index("ix_webhook_deliveries_org_id", "webhook_deliveries", ["org_id"])
    op.create_index("ix_webhook_deliveries_event_type", "webhook_deliveries", ["event_type"])
    op.create_index("ix_webhook_deliveries_status", "webhook_deliveries", ["status"])
    op.create_index("ix_webhook_deliveries_next_retry_at", "webhook_deliveries", ["next_retry_at"])
    op.create_index("ix_webhook_deliveries_created_at", "webhook_deliveries", ["created_at"])
    op.create_index(
        "ix_webhook_deliveries_status_next_retry",
        "webhook_deliveries", ["status", "next_retry_at"],
    )


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
