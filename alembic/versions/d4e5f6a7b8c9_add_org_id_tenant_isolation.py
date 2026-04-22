"""Add org_id columns for tenant isolation.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-04-22 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade():
    # Add org_id to registered_models
    op.add_column("registered_models", sa.Column("org_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_registered_models_org_id", "registered_models", "organizations", ["org_id"], ["id"])
    op.create_index("ix_registered_models_org_id", "registered_models", ["org_id"])

    # Add org_id to incidents
    op.add_column("incidents", sa.Column("org_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_incidents_org_id", "incidents", "organizations", ["org_id"], ["id"])
    op.create_index("ix_incidents_org_id", "incidents", ["org_id"])

    # Add org_id to ai_agents
    op.add_column("ai_agents", sa.Column("org_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_ai_agents_org_id", "ai_agents", "organizations", ["org_id"], ["id"])
    op.create_index("ix_ai_agents_org_id", "ai_agents", ["org_id"])

    # Add org_id to shadow_ai_detections
    op.add_column("shadow_ai_detections", sa.Column("org_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_shadow_ai_detections_org_id", "shadow_ai_detections", "organizations", ["org_id"], ["id"])
    op.create_index("ix_shadow_ai_detections_org_id", "shadow_ai_detections", ["org_id"])

    # Add org_id to governance_policies
    op.add_column("governance_policies", sa.Column("org_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_governance_policies_org_id", "governance_policies", "organizations", ["org_id"], ["id"])
    op.create_index("ix_governance_policies_org_id", "governance_policies", ["org_id"])


def downgrade():
    op.drop_index("ix_governance_policies_org_id", table_name="governance_policies")
    op.drop_constraint("fk_governance_policies_org_id", "governance_policies", type_="foreignkey")
    op.drop_column("governance_policies", "org_id")

    op.drop_index("ix_shadow_ai_detections_org_id", table_name="shadow_ai_detections")
    op.drop_constraint("fk_shadow_ai_detections_org_id", "shadow_ai_detections", type_="foreignkey")
    op.drop_column("shadow_ai_detections", "org_id")

    op.drop_index("ix_ai_agents_org_id", table_name="ai_agents")
    op.drop_constraint("fk_ai_agents_org_id", "ai_agents", type_="foreignkey")
    op.drop_column("ai_agents", "org_id")

    op.drop_index("ix_incidents_org_id", table_name="incidents")
    op.drop_constraint("fk_incidents_org_id", "incidents", type_="foreignkey")
    op.drop_column("incidents", "org_id")

    op.drop_index("ix_registered_models_org_id", table_name="registered_models")
    op.drop_constraint("fk_registered_models_org_id", "registered_models", type_="foreignkey")
    op.drop_column("registered_models", "org_id")
