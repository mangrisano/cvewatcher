"""Application configuration, read once from environment variables.

Every setting the app understands is declared here with its type and default,
so misconfiguration fails fast at startup instead of deep inside a request.
Empty variables count as unset (e.g. ``NVD_API_KEY=`` keeps the default).
"""

from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_ignore_empty=True, extra="ignore")

    database_url: str = "sqlite:///./cvewatcher.db"
    log_level: str = "INFO"

    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    # Fernet key for secrets stored in the DB; derived from the JWT key if unset.
    secrets_encryption_key: Optional[str] = None

    registration_enabled: bool = False
    register_max_attempts: int = 5
    register_window_seconds: int = 3600
    login_max_attempts: int = 5
    login_ip_max_attempts: int = 30
    login_window_seconds: int = 300
    redis_url: Optional[str] = None
    # Comma-separated emails allowed to run admin-only operations.
    admin_emails: str = ""

    nvd_api_key: Optional[str] = None
    nvd_cache_ttl_seconds: int = 600
    nvd_max_concurrency: Optional[int] = None
    enrich_enabled: bool = True

    monitor_enabled: bool = False
    monitor_interval_minutes: int = 360
    # Scan an asset right after it is created, imported or re-identified.
    scan_new_assets: bool = True
    digest_enabled: bool = False
    digest_interval_minutes: int = 1440

    notify_console: bool = True
    notify_webhook_url: Optional[str] = None
    notify_slack_webhook_url: Optional[str] = None
    notify_email_host: Optional[str] = None
    notify_email_port: int = 587
    notify_email_from: Optional[str] = None
    notify_email_to: str = ""
    notify_email_username: Optional[str] = None
    notify_email_password: Optional[str] = None
    notify_email_use_tls: bool = True

    @field_validator("jwt_secret_key")
    @classmethod
    def _strong_secret(cls, value: Optional[str]) -> Optional[str]:
        # RFC 7518 §3.2: an HMAC key must be at least as long as the hash output.
        if value is not None and len(value.encode()) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 bytes long")
        return value

    @field_validator("secrets_encryption_key")
    @classmethod
    def _fernet_key(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            try:
                Fernet(value)
            except ValueError:
                raise ValueError(
                    "SECRETS_ENCRYPTION_KEY must be a Fernet key "
                    "(32 url-safe base64-encoded bytes)"
                ) from None
        return value

    @field_validator("nvd_max_concurrency")
    @classmethod
    def _positive(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 1:
            raise ValueError("NVD_MAX_CONCURRENCY must be a positive integer")
        return value

    @property
    def notify_email_recipients(self) -> list[str]:
        return [
            addr.strip() for addr in self.notify_email_to.split(",") if addr.strip()
        ]

    @property
    def admin_email_set(self) -> set[str]:
        return {e.strip().lower() for e in self.admin_emails.split(",") if e.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
