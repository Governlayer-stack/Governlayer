"""Add model registry, incidents, and governance policies tables.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-16 21:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Model Registry
    op.create_table(
        "registered_models",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("provider", sa.String(100)),
        sa.Column("model_type", sa.String(100)),
        sa.Column("lifecycle", sa.String(20), server_default="development"),
        sa.Column("risk_tier", sa.String(50)),
        sa.Column("description", sa.Text()),
        sa.Column("owner", sa.String(255)),
        sa.Column("tags", sa.JSON(), server_default="[]"),
        sa.Column("metadata", sa.JSON(), server_default="{}"),
        sa.Column("governance_status", sa.String(50), server_default="pending"),
        sa.Column("last_audit_at", sa.DateTime()),
        sa.Column("risk_score", sa.Float()),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    # Model Cards
    op.create_table(
        "model_cards",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("model_id", sa.Integer(), sa.ForeignKey("registered_models.id"), nullable=False),
        sa.Column("intended_use", sa.Text()),
        sa.Column("limitations", sa.Text()),
        sa.Column("training_data_summary", sa.Text()),
        sa.Column("evaluation_metrics", sa.JSON(), server_default="{}"),
        sa.Column("ethical_considerations", sa.Text()),
        sa.Column("fairness_analysis", sa.JSON(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    # Incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("model_id", sa.Integer(), sa.ForeignKey("registered_models.id"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("status", sa.String(20), server_default="open"),
        sa.Column("category", sa.String(100)),
        sa.Column("root_cause", sa.Text()),
        sa.Column("resolution", sa.Text()),
        sa.Column("impact", sa.Text()),
        sa.Column("reporter", sa.String(255)),
        sa.Column("assignee", sa.String(255)),
        sa.Column("timeline", sa.JSON(), server_default="[]"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime()),
    )

    # Governance Policies
    op.create_table(
        "governance_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("version", sa.String(50), server_default="1.0"),
        sa.Column("rules", sa.JSON(), server_default="[]"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("created_by", sa.String(255)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("governance_policies")
    op.drop_table("incidents")
    op.drop_table("model_cards")
    op.drop_table("registered_models")
