"""persist findings so the dashboard reads them from the database

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-09-30 13:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("assets", sa.Column("last_scanned_at", sa.DateTime(timezone=True)))
    op.add_column("cves", sa.Column("kev", sa.Boolean()))
    op.add_column("cves", sa.Column("epss", sa.Float()))
    op.add_column("asset_cves", sa.Column("last_seen", sa.DateTime(timezone=True)))
    op.add_column("asset_cves", sa.Column("relevance_reason", sa.Text()))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("asset_cves", "relevance_reason")
    op.drop_column("asset_cves", "last_seen")
    op.drop_column("cves", "epss")
    op.drop_column("cves", "kev")
    op.drop_column("assets", "last_scanned_at")
