"""P1 batch: agent-scoped API keys, agent budgets, privacy requests.

Revision ID: i9d0e1f2g3h4
Revises: h8c9d0e1f2g3
Create Date: 2026-07-13 23:15:00.000000

Adds:
  - api_keys.agent_id + principal_type (agent identities as first-class
    principals — no shared service accounts).
  - agent_budgets table (step/spend/recursion caps + on_exhaustion policy).
  - privacy_requests table (GDPR Art. 15/17 + CCPA §1798.100/105 workflow).
"""

from alembic import op
import sqlalchemy as sa

revision = "i9d0e1f2g3h4"
down_revision = "h8c9d0e1f2g3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. api_keys — agent principals
    op.add_column("api_keys", sa.Column("agent_id", sa.Integer(), nullable=True))
    op.add_column("api_keys", sa.Column("principal_type", sa.String(16), server_default="user", nullable=False))
    op.create_foreign_key(
        "fk_api_keys_agent_id", "api_keys", "ai_agents", ["agent_id"], ["id"],
    )
    op.create_index("ix_api_keys_agent_id", "api_keys", ["agent_id"])
    # Relax org_id — agent credentials may not have an org (single-tenant deploys)
    op.alter_column("api_keys", "org_id", existing_type=sa.Integer(), nullable=True)

    # 2. agent_budgets
    op.create_table(
        "agent_budgets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("ai_agents.id"), nullable=False, unique=True),
        sa.Column("step_budget", sa.Integer(), nullable=True),
        sa.Column("spend_budget_usd", sa.Float(), nullable=True),
        sa.Column("recursion_depth_limit", sa.Integer(), nullable=True),
        sa.Column("used_steps", sa.Integer(), server_default="0", nullable=False),
        sa.Column("used_spend_usd", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("period", sa.String(16), server_default="total", nullable=False),
        sa.Column("period_start", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("on_exhaustion", sa.String(16), server_default="kill", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_agent_budgets_agent_id", "agent_budgets", ["agent_id"], unique=True)

    # 3. privacy_requests
    op.create_table(
        "privacy_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("request_type", sa.String(16), nullable=False),
        sa.Column("subject_email", sa.String(255), nullable=False),
        sa.Column("status", sa.String(24), server_default="pending", nullable=False),
        sa.Column("submitted_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("due_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("requester", sa.String(255), nullable=True),
        sa.Column("verification_method", sa.String(64), nullable=True),
        sa.Column("verification_notes", sa.Text(), nullable=True),
        sa.Column("records_disclosed", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_deleted", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_anonymized", sa.Integer(), server_default="0", nullable=False),
        sa.Column("downstream_stores_cleared", sa.Text(), nullable=True),
        sa.Column("ledger_decision_id", sa.String(64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_privacy_requests_subject_email", "privacy_requests", ["subject_email"])
    op.create_index("ix_privacy_requests_status", "privacy_requests", ["status"])
    op.create_index("ix_privacy_requests_request_type", "privacy_requests", ["request_type"])


def downgrade() -> None:
    op.drop_table("privacy_requests")
    op.drop_table("agent_budgets")
    op.drop_index("ix_api_keys_agent_id", table_name="api_keys")
    op.drop_constraint("fk_api_keys_agent_id", "api_keys", type_="foreignkey")
    op.drop_column("api_keys", "principal_type")
    op.drop_column("api_keys", "agent_id")
