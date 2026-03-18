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
    conn = op.get_bind()

    # Model Registry
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS registered_models (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            version VARCHAR(50) NOT NULL,
            provider VARCHAR(100),
            model_type VARCHAR(100),
            lifecycle VARCHAR(20) DEFAULT 'development',
            risk_tier VARCHAR(50),
            description TEXT,
            owner VARCHAR(255),
            tags JSON DEFAULT '[]',
            metadata JSON DEFAULT '{}',
            governance_status VARCHAR(50) DEFAULT 'pending',
            last_audit_at TIMESTAMP,
            risk_score FLOAT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_registered_models_name ON registered_models (name)"
    ))

    # Model Cards
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS model_cards (
            id SERIAL PRIMARY KEY,
            model_id INTEGER NOT NULL REFERENCES registered_models(id),
            intended_use TEXT,
            limitations TEXT,
            training_data_summary TEXT,
            evaluation_metrics JSON DEFAULT '{}',
            ethical_considerations TEXT,
            fairness_analysis JSON DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))

    # Incidents
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            model_id INTEGER REFERENCES registered_models(id),
            title VARCHAR(500) NOT NULL,
            description TEXT,
            severity VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'open',
            category VARCHAR(100),
            root_cause TEXT,
            resolution TEXT,
            impact TEXT,
            reporter VARCHAR(255),
            assignee VARCHAR(255),
            timeline JSON DEFAULT '[]',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            resolved_at TIMESTAMP
        )
    """))

    # Governance Policies
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS governance_policies (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL UNIQUE,
            description TEXT,
            version VARCHAR(50) DEFAULT '1.0',
            rules JSON DEFAULT '[]',
            is_active BOOLEAN DEFAULT TRUE,
            created_by VARCHAR(255),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))


def downgrade() -> None:
    op.drop_table("governance_policies")
    op.drop_table("incidents")
    op.drop_table("model_cards")
    op.drop_table("registered_models")
