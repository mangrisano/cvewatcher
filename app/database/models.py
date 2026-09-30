from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    TypeDecorator,
    true,
)
from uuid import uuid4
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from app.database.connection import Base
from app.utils import crypto


class EncryptedString(TypeDecorator):
    """Text encrypted at rest; reads as None if the key can't decrypt it."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else crypto.encrypt(value)

    def process_result_value(self, value, dialect):
        return None if value is None else crypto.decrypt(value)


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
    ecosystem = Column(String(50), nullable=True)
    user_email = Column(String(100), nullable=False, index=True)
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
    publish_date = Column(DateTime, index=True)
    modified_date = Column(DateTime, server_default=func.now(), onupdate=func.now())
    affected_products = Column(JSON)

    def __repr__(self):
        return (
            f"<CVE(id='{self.id}', severity='{self.severity}', score='{self.score}')>"
        )


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti = Column(String(64), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    def __repr__(self):
        return f"<RevokedToken(jti='{self.jti}')>"


class AssetCVE(Base):
    """Association of an asset with a CVE that affects it.

    Keeps the per-user "this asset is affected by this CVE" link out of the
    shared ``cves`` table, so global CVE rows never carry tenant data.
    """

    __tablename__ = "asset_cves"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    cve_id = Column(
        String(20),
        ForeignKey("cves.id", ondelete="CASCADE"),
        primary_key=True,
    )
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    # Triage state: open | acknowledged | fixed | false_positive | accepted_risk.
    status = Column(String(20), nullable=False, server_default="open")
    notes = Column(Text, nullable=True)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # Last KEV/severity seen by monitoring, to detect escalations; NULL until
    # first observed, so existing findings get a silent baseline.
    kev = Column(Boolean, nullable=True)
    severity = Column(String(20), nullable=True)

    def __repr__(self):
        return f"<AssetCVE(asset_id='{self.asset_id}', cve_id='{self.cve_id}')>"


class NotificationPreference(Base):
    """A user's alert settings; users without a row get the defaults."""

    __tablename__ = "notification_preferences"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    min_severity = Column(
        String(10), nullable=False, default="HIGH", server_default="HIGH"
    )
    always_kev = Column(Boolean, nullable=False, default=True, server_default=true())
    escalations = Column(Boolean, nullable=False, default=True, server_default=true())
    slack_webhook_url = Column(EncryptedString, nullable=True)
    teams_webhook_url = Column(EncryptedString, nullable=True)
    discord_webhook_url = Column(EncryptedString, nullable=True)
    telegram_bot_token = Column(EncryptedString, nullable=True)
    telegram_chat_id = Column(String(64), nullable=True)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
