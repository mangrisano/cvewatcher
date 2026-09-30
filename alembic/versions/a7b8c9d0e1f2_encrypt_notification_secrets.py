"""encrypt notification secrets at rest

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-09-30 11:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.utils import crypto


# revision identifiers, used by Alembic.
revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, Sequence[str], None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SECRETS = {
    "slack_webhook_url": 500,
    "teams_webhook_url": 500,
    "discord_webhook_url": 500,
    "telegram_bot_token": 100,
}


def _rewrite(convert) -> None:
    conn = op.get_bind()
    columns = ", ".join(_SECRETS)
    rows = conn.execute(
        sa.text(f"SELECT user_id, {columns} FROM notification_preferences")
    ).mappings()
    for row in list(rows):
        values = {name: convert(row[name]) if row[name] else None for name in _SECRETS}
        assignments = ", ".join(f"{name} = :{name}" for name in _SECRETS)
        conn.execute(
            sa.text(
                f"UPDATE notification_preferences SET {assignments} "
                "WHERE user_id = :user_id"
            ),
            {**values, "user_id": row["user_id"]},
        )


def upgrade() -> None:
    """Upgrade schema."""
    for name in _SECRETS:
        op.alter_column(
            "notification_preferences", name, type_=sa.Text(), existing_nullable=True
        )
    _rewrite(crypto.encrypt)


def downgrade() -> None:
    """Downgrade schema."""
    _rewrite(crypto.decrypt)
    for name, length in _SECRETS.items():
        op.alter_column(
            "notification_preferences",
            name,
            type_=sa.String(length=length),
            existing_nullable=True,
        )
