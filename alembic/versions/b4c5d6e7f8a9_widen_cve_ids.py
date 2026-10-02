"""widen CVE ids for long advisory identifiers

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-10-02 12:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "b4c5d6e7f8a9"
down_revision: Union[str, Sequence[str], None] = "a3b4c5d6e7f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (("cves", "id"), ("asset_cves", "cve_id"))


def _resize(length: int) -> None:
    # SQLite does not enforce VARCHAR lengths.
    if op.get_bind().dialect.name == "sqlite":
        return
    for table, column in _COLUMNS:
        op.alter_column(
            table, column, type_=sa.String(length=length), existing_nullable=False
        )


def upgrade() -> None:
    """Upgrade schema."""
    _resize(64)


def downgrade() -> None:
    """Downgrade schema."""
    # Ids that no longer fit are dropped, with their asset links.
    op.execute("DELETE FROM asset_cves WHERE length(cve_id) > 20")
    op.execute("DELETE FROM cves WHERE length(id) > 20")
    _resize(20)
