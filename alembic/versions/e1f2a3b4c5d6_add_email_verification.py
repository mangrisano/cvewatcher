"""add email verification for new sign-ups

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-09-30 16:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "d0e1f2a3b4c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing accounts predate verification: they count as verified.
    op.add_column(
        "users",
        sa.Column(
            "email_verified", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.create_table(
        "email_verification_tokens",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_email_verification_tokens_user_id",
        "email_verification_tokens",
        ["user_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_email_verification_tokens_user_id", "email_verification_tokens")
    op.drop_table("email_verification_tokens")
    op.drop_column("users", "email_verified")
