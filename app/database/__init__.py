from app.database.connection import engine, Base, get_db
from app.database.models import User, Asset, CVE


def create_tables():
    """Crea tutte le tabelle del database."""
    Base.metadata.create_all(bind=engine)


__all__ = ["User", "Asset", "CVE", "get_db", "create_tables"]
