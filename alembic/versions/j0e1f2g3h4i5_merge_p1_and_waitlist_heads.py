"""Merge revision to reconcile the P1 head with the waitlist head.

Revision ID: j0e1f2g3h4i5
Revises: i9d0e1f2g3h4, d4e5f6a7b8ca
Create Date: 2026-07-13 23:35:00.000000

Alembic's `upgrade head` had been failing because of two independent heads:
  * i9d0e1f2g3h4 — the P1 batch (agent identities, budgets, privacy).
  * d4e5f6a7b8ca — the waitlist / demo-requests tables (renamed from a
    duplicate d4e5f6a7b8c9 revision that shipped by mistake).

This merge revision unifies them so future migrations descend cleanly.
No schema changes here.
"""

from alembic import op

revision = "j0e1f2g3h4i5"
down_revision = ("i9d0e1f2g3h4", "d4e5f6a7b8ca")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
