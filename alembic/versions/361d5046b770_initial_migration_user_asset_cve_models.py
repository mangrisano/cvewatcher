from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "361d5046b770"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("version", sa.String(length=50), nullable=True))
    op.add_column(
        "assets", sa.Column("user_email", sa.String(length=100), nullable=False)
    )
    op.add_column("cves", sa.Column("summary", sa.Text(), nullable=True))
    op.add_column("cves", sa.Column("severity", sa.String(length=20), nullable=True))
    op.add_column("cves", sa.Column("score", sa.Float(), nullable=True))
    op.add_column("cves", sa.Column("publish_date", sa.DateTime(), nullable=True))
    op.add_column(
        "cves",
        sa.Column(
            "modified_date",
            sa.DateTime(),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=True,
        ),
    )
    op.add_column("cves", sa.Column("affected_products", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("cves", "affected_products")
    op.drop_column("cves", "modified_date")
    op.drop_column("cves", "publish_date")
    op.drop_column("cves", "score")
    op.drop_column("cves", "severity")
    op.drop_column("cves", "summary")
    op.drop_column("assets", "user_email")
    op.drop_column("assets", "version")
