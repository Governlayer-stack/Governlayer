"""ERG batch: eval-mode state, agent lockdown states, batch_id, attestations, spec-gaming.

Revision ID: l2g3h4i5j6k7
Revises: k1f2g3h4i5j6
Create Date: 2026-08-10 12:00:00.000000

Adds:
  - AgentStatus enum values WARNED, LOCKED_DOWN (four-tier circuit breaker).
  - ai_agents.batch_id column (agents in the same eval batch share this).
  - eval_mode_state, attestations, spec_gaming_events tables.
"""

from alembic import op
import sqlalchemy as sa

revision = "l2g3h4i5j6k7"
down_revision = "k1f2g3h4i5j6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Extend the agentstatus enum (Postgres requires autocommit)
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE agentstatus ADD VALUE IF NOT EXISTS 'WARNED'")
            op.execute("ALTER TYPE agentstatus ADD VALUE IF NOT EXISTS 'LOCKED_DOWN'")

    # 2. batch_id on ai_agents
    op.add_column("ai_agents", sa.Column("batch_id", sa.String(64), nullable=True))
    op.create_index("ix_ai_agents_batch_id", "ai_agents", ["batch_id"])

    # 3. eval_mode_state
    op.create_table(
        "eval_mode_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("activated_at", sa.DateTime(), nullable=True),
        sa.Column("deactivated_at", sa.DateTime(), nullable=True),
        sa.Column("activated_by", sa.String(255), nullable=True),
        sa.Column("downgraded_categories", sa.Text(),
                  server_default="content_safety,toxicity,bias_content", nullable=False),
        sa.Column("elevated_categories", sa.Text(),
                  server_default="boundary,identity,data_egress,network_scope", nullable=False),
        sa.Column("ledger_decision_id", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_eval_mode_state_org_id", "eval_mode_state", ["org_id"], unique=True)

    # 4. attestations
    op.create_table(
        "attestations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("ai_agents.id"), nullable=True),
        sa.Column("batch_id", sa.String(64), nullable=True),
        sa.Column("target_system", sa.String(255), nullable=False),
        sa.Column("target_endpoint", sa.String(2048), nullable=True),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("scope_summary", sa.Text(), nullable=False),
        sa.Column("attestation_id", sa.String(64), nullable=False, unique=True),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signed_by", sa.String(255), nullable=False),
        sa.Column("ledger_decision_id", sa.String(64), nullable=True),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("valid_until", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(24), server_default="active", nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_attestations_org_id", "attestations", ["org_id"])
    op.create_index("ix_attestations_agent_id", "attestations", ["agent_id"])
    op.create_index("ix_attestations_batch_id", "attestations", ["batch_id"])
    op.create_index("ix_attestations_target_system", "attestations", ["target_system"])
    op.create_index("ix_attestations_attestation_id", "attestations", ["attestation_id"], unique=True)
    op.create_index("ix_attestations_status", "attestations", ["status"])

    # 5. spec_gaming_events
    op.create_table(
        "spec_gaming_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("ai_agents.id"), nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.Column("blocked_decision_id", sa.String(64), nullable=False),
        sa.Column("retry_decision_id", sa.String(64), nullable=False),
        sa.Column("similarity_score", sa.Float(), nullable=False),
        sa.Column("time_between_seconds", sa.Float(), nullable=False),
        sa.Column("action_taken", sa.String(24), nullable=False),
        sa.Column("escalation_id", sa.String(64), nullable=True),
        sa.Column("ledger_decision_id", sa.String(64), nullable=True),
        sa.Column("detected_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_spec_gaming_events_agent_id", "spec_gaming_events", ["agent_id"])
    op.create_index("ix_spec_gaming_events_org_id", "spec_gaming_events", ["org_id"])
    op.create_index("ix_spec_gaming_agent_time", "spec_gaming_events", ["agent_id", "detected_at"])


def downgrade() -> None:
    op.drop_table("spec_gaming_events")
    op.drop_table("attestations")
    op.drop_table("eval_mode_state")
    op.drop_index("ix_ai_agents_batch_id", table_name="ai_agents")
    op.drop_column("ai_agents", "batch_id")
    # Enum values are not dropped in downgrade — Postgres doesn't support it cleanly.
