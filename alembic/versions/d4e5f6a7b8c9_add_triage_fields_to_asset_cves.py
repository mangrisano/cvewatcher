"""add triage fields (status, notes, updated_at) to asset_cves

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-08-05 12:45:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "asset_cves",
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="open"
        ),
    )
    op.add_column("asset_cves", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column(
        "asset_cves",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("asset_cves", "updated_at")
    op.drop_column("asset_cves", "notes")
    op.drop_column("asset_cves", "status")
