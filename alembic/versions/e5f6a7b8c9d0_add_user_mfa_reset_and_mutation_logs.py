"""Add MFA and password reset columns to users, plus mutation_logs table.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-17 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Password reset columns (IF NOT EXISTS for idempotency)
    conn.execute(sa.text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(64)"
    ))
    conn.execute(sa.text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMP"
    ))

    # MFA columns
    conn.execute(sa.text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32)"
    ))
    conn.execute(sa.text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL"
    ))
    conn.execute(sa.text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes TEXT"
    ))

    # Mutation audit log table
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS mutation_logs (
            id SERIAL PRIMARY KEY,
            actor VARCHAR(255) NOT NULL,
            action VARCHAR(50) NOT NULL,
            resource_type VARCHAR(100) NOT NULL,
            resource_id VARCHAR(100),
            details TEXT,
            created_at TIMESTAMP DEFAULT NOW() NOT NULL
        )
    """))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_mutation_logs_id ON mutation_logs (id)"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_mutation_logs_created_at ON mutation_logs (created_at)"
    ))


def downgrade() -> None:
    op.drop_index("ix_mutation_logs_created_at", table_name="mutation_logs")
    op.drop_index("ix_mutation_logs_id", table_name="mutation_logs")
    op.drop_table("mutation_logs")
    op.drop_column("users", "mfa_backup_codes")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "reset_token_expires_at")
    op.drop_column("users", "reset_token")
