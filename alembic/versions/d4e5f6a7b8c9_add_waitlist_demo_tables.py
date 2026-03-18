"""Add waitlist and demo request tables.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-16 23:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS waitlist (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            company VARCHAR(255),
            role VARCHAR(100),
            use_case TEXT,
            source VARCHAR(100) DEFAULT 'website',
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_waitlist_email ON waitlist (email)"
    ))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS demo_requests (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            company VARCHAR(255),
            role VARCHAR(100),
            team_size VARCHAR(50),
            use_case TEXT,
            frameworks_interested TEXT,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_demo_requests_email ON demo_requests (email)"
    ))


def downgrade() -> None:
    op.drop_table("demo_requests")
    op.drop_table("waitlist")
