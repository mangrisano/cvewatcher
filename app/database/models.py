from sqlalchemy import Column, String, DateTime, Text, Float, JSON
from uuid import uuid4
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from app.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid4)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid4)
    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=True)
    cpe = Column(String(255), nullable=True)
    user_email = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Asset(name='{self.name}', cpe='{self.cpe}')>"


class CVE(Base):
    __tablename__ = "cves"

    id = Column(String(20), primary_key=True)
    summary = Column(Text)
    severity = Column(String(20))
    score = Column(Float)
    publish_date = Column(DateTime)
    modified_date = Column(DateTime, server_default=func.now(), onupdate=func.now())
    affected_products = Column(JSON)

    def __repr__(self):
        return (
            f"<CVE(id='{self.id}', severity='{self.severity}', score='{self.score}')>"
        )
