import os
from pathlib import Path

from app.database.connection import engine, Base, get_db
from app.database.models import User, Asset, CVE, RevokedToken, AssetCVE


def create_tables():
    Base.metadata.create_all(bind=engine)


def init_schema():
    """Bring the database schema up to date on startup.

    Alembic's migrations use Postgres-specific types (UUID, ...), so they
    can't run against the SQLite databases used for local/dev/test runs —
    those fall back to a plain create_all(). Postgres always goes through
    Alembic so an existing deployment picks up schema changes on upgrade,
    not just brand-new databases.
    """
    database_url = os.getenv("DATABASE_URL", "")
    if database_url.startswith("sqlite"):
        create_tables()
        return

    from alembic.config import Config
    from alembic import command

    repo_root = Path(__file__).resolve().parent.parent.parent
    alembic_cfg = Config(str(repo_root / "alembic.ini"))
    command.upgrade(alembic_cfg, "head")


__all__ = [
    "User",
    "Asset",
    "CVE",
    "RevokedToken",
    "AssetCVE",
    "get_db",
    "create_tables",
    "init_schema",
]
