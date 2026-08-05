"""add indexes on assets.user_email and cves.publish_date

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-08-05 11:30:00.000000

Every asset query filters by ``user_email`` and ``/cves/recent`` orders by
``publish_date``; both columns were unindexed and caused full scans.
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index(
        op.f("ix_assets_user_email"), "assets", ["user_email"], unique=False
    )
    op.create_index(
        op.f("ix_cves_publish_date"), "cves", ["publish_date"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_cves_publish_date"), table_name="cves")
    op.drop_index(op.f("ix_assets_user_email"), table_name="assets")
