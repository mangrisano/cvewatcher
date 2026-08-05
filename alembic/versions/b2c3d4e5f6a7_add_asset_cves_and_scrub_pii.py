"""add asset_cves association and scrub tenant data from cves

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-08-05 11:10:00.000000

Introduces the ``asset_cves`` association table so a CVE can be linked to the
assets it affects without storing tenant data (asset name / owner email) inside
the shared ``cves`` table. Existing per-asset tracking previously kept in
``cves.affected_products`` is backfilled into the association and then scrubbed
from the shared rows (the scrub is not reversible).
"""

from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "asset_cves",
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id", "cve_id"),
    )
    _backfill_and_scrub()


def _backfill_and_scrub() -> None:
    bind = op.get_bind()
    meta = sa.MetaData()
    cves = sa.Table(
        "cves",
        meta,
        sa.Column("id", sa.String(20)),
        sa.Column("affected_products", sa.JSON()),
    )
    assets = sa.Table(
        "assets",
        meta,
        sa.Column("id", sa.UUID()),
        sa.Column("name", sa.String(100)),
        sa.Column("version", sa.String(50)),
        sa.Column("user_email", sa.String(100)),
    )
    asset_cves = sa.Table(
        "asset_cves",
        meta,
        sa.Column("asset_id", sa.UUID()),
        sa.Column("cve_id", sa.String(20)),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
    )

    now = datetime.now(timezone.utc)
    rows = bind.execute(sa.select(cves.c.id, cves.c.affected_products)).fetchall()
    for cve_id, products in rows:
        if not isinstance(products, list):
            continue
        tracking = [p for p in products if isinstance(p, dict) and "user_email" in p]
        if not tracking:
            continue

        for entry in tracking:
            conditions = [
                assets.c.name == entry.get("asset_name"),
                assets.c.user_email == entry.get("user_email"),
            ]
            version = entry.get("asset_version")
            if version is not None:
                conditions.append(assets.c.version == version)

            asset_ids = bind.execute(
                sa.select(assets.c.id).where(sa.and_(*conditions))
            ).fetchall()
            for (asset_id,) in asset_ids:
                already_linked = bind.execute(
                    sa.select(asset_cves.c.cve_id).where(
                        asset_cves.c.asset_id == asset_id,
                        asset_cves.c.cve_id == cve_id,
                    )
                ).first()
                if not already_linked:
                    bind.execute(
                        asset_cves.insert().values(
                            asset_id=asset_id, cve_id=cve_id, first_seen=now
                        )
                    )

        kept = [p for p in products if not (isinstance(p, dict) and "user_email" in p)]
        bind.execute(
            cves.update()
            .where(cves.c.id == cve_id)
            .values(affected_products=kept or None)
        )


def downgrade() -> None:
    """Downgrade schema (the tenant-data scrub is not reversible)."""
    op.drop_table("asset_cves")
