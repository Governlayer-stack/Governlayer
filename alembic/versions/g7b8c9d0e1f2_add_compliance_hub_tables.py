"""Add compliance hub tables (programs, policies, audits).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-08 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "g7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS compliance_programs (
            id VARCHAR(64) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            frameworks TEXT NOT NULL,
            owner VARCHAR(255) NOT NULL,
            start_date VARCHAR(10) NOT NULL,
            target_audit_date VARCHAR(10) NOT NULL,
            controls TEXT NOT NULL,
            created_at VARCHAR(30) NOT NULL
        )
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_compliance_programs_id ON compliance_programs (id)
    """))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS compliance_policies (
            id VARCHAR(64) PRIMARY KEY,
            program_id VARCHAR(64) NOT NULL REFERENCES compliance_programs(id) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            summary TEXT,
            sections TEXT,
            applicable_frameworks TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'draft',
            version VARCHAR(20) NOT NULL DEFAULT '1.0',
            word_count INTEGER,
            generated_by VARCHAR(255),
            generated_at VARCHAR(30),
            last_modified_by VARCHAR(255)
        )
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_compliance_policies_id ON compliance_policies (id)
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_compliance_policies_program_id ON compliance_policies (program_id)
    """))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS compliance_audits (
            id VARCHAR(64) PRIMARY KEY,
            program_id VARCHAR(64) NOT NULL REFERENCES compliance_programs(id) ON DELETE CASCADE,
            auditor_firm VARCHAR(255) NOT NULL,
            proposed_date VARCHAR(10) NOT NULL,
            audit_type VARCHAR(20) NOT NULL,
            notes TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'scheduled',
            readiness_at_scheduling FLOAT,
            scheduled_by VARCHAR(255),
            scheduled_at VARCHAR(30)
        )
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_compliance_audits_id ON compliance_audits (id)
    """))
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_compliance_audits_program_id ON compliance_audits (program_id)
    """))


def downgrade() -> None:
    op.drop_table("compliance_audits")
    op.drop_table("compliance_policies")
    op.drop_table("compliance_programs")
