from app.database.connection import engine, Base, get_db
from app.database.models import User, Asset, CVE, RevokedToken, AssetCVE


def create_tables():
    Base.metadata.create_all(bind=engine)


__all__ = [
    "User",
    "Asset",
    "CVE",
    "RevokedToken",
    "AssetCVE",
    "get_db",
    "create_tables",
]
