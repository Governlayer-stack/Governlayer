"""Add agent registry and shadow AI detection tables.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-03-16 22:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_agents",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("agent_type", sa.String(20), server_default="autonomous"),
        sa.Column("status", sa.String(20), server_default="under_review"),
        sa.Column("description", sa.Text()),
        sa.Column("owner", sa.String(255)),
        sa.Column("team", sa.String(255)),
        sa.Column("purpose", sa.Text()),
        sa.Column("tools", sa.JSON(), server_default="[]"),
        sa.Column("data_sources", sa.JSON(), server_default="[]"),
        sa.Column("permissions", sa.JSON(), server_default="[]"),
        sa.Column("guardrails", sa.JSON(), server_default="[]"),
        sa.Column("autonomy_level", sa.Integer(), server_default="1"),
        sa.Column("model_provider", sa.String(100)),
        sa.Column("model_name", sa.String(255)),
        sa.Column("model_id", sa.Integer(), sa.ForeignKey("registered_models.id"), nullable=True),
        sa.Column("risk_tier", sa.String(50)),
        sa.Column("risk_score", sa.Float()),
        sa.Column("governance_status", sa.String(50), server_default="pending"),
        sa.Column("last_audit_at", sa.DateTime()),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("approved_at", sa.DateTime()),
        sa.Column("dependencies", sa.JSON(), server_default="[]"),
        sa.Column("upstream_services", sa.JSON(), server_default="[]"),
        sa.Column("downstream_services", sa.JSON(), server_default="[]"),
        sa.Column("discovery_source", sa.String(20), server_default="manual"),
        sa.Column("is_shadow", sa.Boolean(), server_default="false"),
        sa.Column("first_seen_at", sa.DateTime()),
        sa.Column("last_activity_at", sa.DateTime()),
        sa.Column("tags", sa.JSON(), server_default="[]"),
        sa.Column("metadata", sa.JSON(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "agent_cards",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("ai_agents.id"), nullable=False, unique=True),
        sa.Column("intended_use", sa.Text()),
        sa.Column("limitations", sa.Text()),
        sa.Column("ethical_considerations", sa.Text()),
        sa.Column("interaction_patterns", sa.JSON(), server_default="[]"),
        sa.Column("failure_modes", sa.JSON(), server_default="[]"),
        sa.Column("escalation_policy", sa.Text()),
        sa.Column("data_retention", sa.Text()),
        sa.Column("compliance_notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "shadow_ai_detections",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("detection_type", sa.String(100), nullable=False),
        sa.Column("source", sa.String(255)),
        sa.Column("description", sa.Text()),
        sa.Column("evidence", sa.JSON(), server_default="{}"),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("status", sa.String(20), server_default="new"),
        sa.Column("detected_service", sa.String(255)),
        sa.Column("detected_model", sa.String(255)),
        sa.Column("detected_by", sa.String(255)),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("ai_agents.id"), nullable=True),
        sa.Column("remediation", sa.Text()),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("shadow_ai_detections")
    op.drop_table("agent_cards")
    op.drop_table("ai_agents")
