"""Add KILLED to agentstatus enum for SR 26-2 kill switch.

Revision ID: h8c9d0e1f2g3
Revises: g7b8c9d0e1f2
Create Date: 2026-07-13 23:00:00.000000

SR 26-2 §V.3 (Federal Reserve, effective 2026-04-17) and OCC Bulletin
2026-13 require every AI/ML system that takes autonomous action to have a
documented kill-switch capability. This migration adds the terminal
KILLED status to the agentstatus enum so POST /v1/agents/{id}/kill can
transition an agent into an unresurrectable state.
"""

from alembic import op

revision = "h8c9d0e1f2g3"
down_revision = "g7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Postgres requires enum values to be added outside a transaction block.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE agentstatus ADD VALUE IF NOT EXISTS 'KILLED'")
    # SQLite / other backends: enums are stored as strings, no schema change needed.


def downgrade() -> None:
    # Postgres does not support removing enum values without recreating the
    # type. Downgrade is a no-op — the KILLED value stays but is unused.
    pass
