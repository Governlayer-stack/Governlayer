"""Add vendor risk management tables.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-08 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vendors",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("services", sa.Text(), nullable=True),
        sa.Column("data_shared", sa.Text(), nullable=True),
        sa.Column("ai_usage", sa.String(1000), nullable=True),
        sa.Column("compliance_certifications", sa.Text(), nullable=True),
        sa.Column("contract_end_date", sa.DateTime(), nullable=True),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("questionnaire_status", sa.String(50), nullable=False, server_default="not_sent"),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("risk_details", sa.Text(), nullable=True),
        sa.Column("last_assessed", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vendors_name", "vendors", ["name"], unique=False)

    op.create_table(
        "vendor_assessments",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("vendor_id", sa.String(36), nullable=False),
        sa.Column("assessment_type", sa.String(50), nullable=False, server_default="deterministic"),
        sa.Column("scores", sa.Text(), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("assessed_by", sa.String(255), nullable=False),
        sa.Column("assessed_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["vendor_id"], ["vendors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vendor_assessments_vendor_id", "vendor_assessments", ["vendor_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vendor_assessments_vendor_id", table_name="vendor_assessments")
    op.drop_table("vendor_assessments")
    op.drop_index("ix_vendors_name", table_name="vendors")
    op.drop_table("vendors")
