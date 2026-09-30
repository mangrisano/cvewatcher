from pathlib import Path

from app.database.connection import DATABASE_URL, engine, Base, get_db
from app.database.models import (
    CVE,
    Asset,
    AssetCVE,
    EmailVerificationToken,
    NotificationPreference,
    PasswordResetToken,
    RevokedToken,
    User,
)


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
    if engine.dialect.name == "sqlite":
        create_tables()
        return

    from alembic.config import Config
    from alembic import command

    # Built without a config *file* on purpose: alembic/env.py calls
    # fileConfig(config.config_file_name) when one is set, and fileConfig()
    # defaults to disable_existing_loggers=True — which would silently
    # disable every other logger in this process (including uvicorn's own),
    # since alembic.ini only declares root/sqlalchemy/alembic loggers.
    repo_root = Path(__file__).resolve().parent.parent.parent
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", str(repo_root / "alembic"))
    # Escape "%" (e.g. URL-encoded passwords): Alembic options go through configparser.
    alembic_cfg.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    command.upgrade(alembic_cfg, "head")


__all__ = [
    "User",
    "Asset",
    "CVE",
    "RevokedToken",
    "AssetCVE",
    "NotificationPreference",
    "PasswordResetToken",
    "EmailVerificationToken",
    "get_db",
    "create_tables",
    "init_schema",
]
