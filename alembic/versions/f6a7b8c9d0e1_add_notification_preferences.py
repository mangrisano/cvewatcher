"""add notification preferences and last-seen finding state

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-09-30 10:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "notification_preferences",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "min_severity", sa.String(length=10), nullable=False, server_default="HIGH"
        ),
        sa.Column("always_kev", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "escalations", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("slack_webhook_url", sa.String(length=500), nullable=True),
        sa.Column("teams_webhook_url", sa.String(length=500), nullable=True),
        sa.Column("discord_webhook_url", sa.String(length=500), nullable=True),
        sa.Column("telegram_bot_token", sa.String(length=100), nullable=True),
        sa.Column("telegram_chat_id", sa.String(length=64), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
    )
    op.add_column("asset_cves", sa.Column("kev", sa.Boolean(), nullable=True))
    op.add_column(
        "asset_cves", sa.Column("severity", sa.String(length=20), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("asset_cves", "severity")
    op.drop_column("asset_cves", "kev")
    op.drop_table("notification_preferences")
