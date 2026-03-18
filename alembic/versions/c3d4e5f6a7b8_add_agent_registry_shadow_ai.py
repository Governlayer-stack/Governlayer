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
    conn = op.get_bind()

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS ai_agents (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            agent_type VARCHAR(20) DEFAULT 'autonomous',
            status VARCHAR(20) DEFAULT 'under_review',
            description TEXT,
            owner VARCHAR(255),
            team VARCHAR(255),
            purpose TEXT,
            tools JSON DEFAULT '[]',
            data_sources JSON DEFAULT '[]',
            permissions JSON DEFAULT '[]',
            guardrails JSON DEFAULT '[]',
            autonomy_level INTEGER DEFAULT 1,
            model_provider VARCHAR(100),
            model_name VARCHAR(255),
            model_id INTEGER REFERENCES registered_models(id),
            risk_tier VARCHAR(50),
            risk_score FLOAT,
            governance_status VARCHAR(50) DEFAULT 'pending',
            last_audit_at TIMESTAMP,
            approved_by VARCHAR(255),
            approved_at TIMESTAMP,
            dependencies JSON DEFAULT '[]',
            upstream_services JSON DEFAULT '[]',
            downstream_services JSON DEFAULT '[]',
            discovery_source VARCHAR(20) DEFAULT 'manual',
            is_shadow BOOLEAN DEFAULT FALSE,
            first_seen_at TIMESTAMP,
            last_activity_at TIMESTAMP,
            tags JSON DEFAULT '[]',
            metadata JSON DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_ai_agents_name ON ai_agents (name)"
    ))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS agent_cards (
            id SERIAL PRIMARY KEY,
            agent_id INTEGER NOT NULL UNIQUE REFERENCES ai_agents(id),
            intended_use TEXT,
            limitations TEXT,
            ethical_considerations TEXT,
            interaction_patterns JSON DEFAULT '[]',
            failure_modes JSON DEFAULT '[]',
            escalation_policy TEXT,
            data_retention TEXT,
            compliance_notes TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS shadow_ai_detections (
            id SERIAL PRIMARY KEY,
            detection_type VARCHAR(100) NOT NULL,
            source VARCHAR(255),
            description TEXT,
            evidence JSON DEFAULT '{}',
            severity VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'new',
            detected_service VARCHAR(255),
            detected_model VARCHAR(255),
            detected_by VARCHAR(255),
            agent_id INTEGER REFERENCES ai_agents(id),
            remediation TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))


def downgrade() -> None:
    op.drop_table("shadow_ai_detections")
    op.drop_table("agent_cards")
    op.drop_table("ai_agents")
