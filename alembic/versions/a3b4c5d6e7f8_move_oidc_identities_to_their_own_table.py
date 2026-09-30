"""move OpenID Connect identities to their own table

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-09-30 20:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "a3b4c5d6e7f8"
down_revision: Union[str, Sequence[str], None] = "f2a3b4c5d6e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # One account can now sign in through several providers.
    op.create_table(
        "user_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("issuer", "subject", name="uq_user_identities_identity"),
    )
    op.create_index("ix_user_identities_user_id", "user_identities", ["user_id"])
    op.execute(
        "INSERT INTO user_identities (id, user_id, issuer, subject) "
        "SELECT gen_random_uuid(), id, oidc_issuer, oidc_subject FROM users "
        "WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL"
    )
    op.drop_constraint("uq_users_oidc_identity", "users", type_="unique")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "oidc_issuer")


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column("users", sa.Column("oidc_issuer", sa.String(length=255)))
    op.add_column("users", sa.Column("oidc_subject", sa.String(length=255)))
    op.create_unique_constraint(
        "uq_users_oidc_identity", "users", ["oidc_issuer", "oidc_subject"]
    )
    # The old schema holds one identity per account: keep the oldest.
    op.execute(
        "UPDATE users SET oidc_issuer = i.issuer, oidc_subject = i.subject "
        "FROM (SELECT DISTINCT ON (user_id) user_id, issuer, subject "
        "FROM user_identities ORDER BY user_id, created_at) AS i "
        "WHERE users.id = i.user_id"
    )
    op.drop_index("ix_user_identities_user_id", "user_identities")
    op.drop_table("user_identities")
