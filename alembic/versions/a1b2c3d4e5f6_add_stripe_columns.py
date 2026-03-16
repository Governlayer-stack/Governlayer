"""Add Stripe billing columns to organizations.

Revision ID: a1b2c3d4e5f6
Revises: 5b38b2c055f0
Create Date: 2026-03-16 14:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f6"
down_revision = "5b38b2c055f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("stripe_customer_id", sa.String(255), nullable=True))
    op.add_column("organizations", sa.Column("stripe_subscription_id", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("organizations", "stripe_subscription_id")
    op.drop_column("organizations", "stripe_customer_id")
