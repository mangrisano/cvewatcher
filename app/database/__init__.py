from app.database.connection import engine, Base, get_db
from app.database.models import User, Asset, CVE

def create_tables():
    Base.metadata.create_all(bind=engine)

__all__ = ["User", "Asset", "CVE", "get_db", "create_tables"]
