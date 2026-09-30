"""Application configuration, read once from environment variables.

Every setting the app understands is declared here with its type and default,
so misconfiguration fails fast at startup instead of deep inside a request.
Empty variables count as unset (e.g. ``NVD_API_KEY=`` keeps the default).
"""

from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet
from pydantic import BaseModel, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LEGACY_OIDC_PROVIDER = "default"


class OidcProviderSettings(BaseModel):
    """One OpenID Connect provider, from ``OIDC_PROVIDERS__<ID>__<FIELD>``."""

    issuer: str
    client_id: str
    client_secret: Optional[str] = None
    # Where the app itself fetches the discovery document, when the issuer URL is
    # not reachable from the server (e.g. a provider in the same Docker network).
    discovery_url: Optional[str] = None
    # Button label; defaults to the capitalised provider id.
    name: Optional[str] = None
    # Icon file in app/static/img/providers (without .svg); defaults to the id.
    icon: Optional[str] = None
    scopes: str = "openid email profile"
    auto_create: bool = True
    allowed_domains: str = ""

    @field_validator("icon")
    @classmethod
    def _icon_name(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not value.replace("-", "").replace("_", "").isalnum():
            raise ValueError("an OIDC icon name may only use letters, digits, - and _")
        return value

    @property
    def allowed_domain_set(self) -> set[str]:
        return {
            d.strip().lower().lstrip("@")
            for d in self.allowed_domains.split(",")
            if d.strip()
        }


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_ignore_empty=True, extra="ignore", env_nested_delimiter="__"
    )

    database_url: str = "sqlite:///./cvewatcher.db"
    log_level: str = "INFO"

    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    # Fernet key for secrets stored in the DB; derived from the JWT key if unset.
    secrets_encryption_key: Optional[str] = None

    registration_enabled: bool = False
    # Base URL users reach the app at, used in emailed links (password reset).
    public_url: Optional[str] = None

    # Single sign-on: any number of OpenID Connect providers, keyed by an id
    # (OIDC_PROVIDERS__GOOGLE__ISSUER=... -> "google").
    oidc_providers: dict[str, OidcProviderSettings] = {}
    # The single-provider variables of 2.12.0, still read as provider "default".
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_discovery_url: Optional[str] = None
    oidc_provider_name: str = "SSO"
    oidc_scopes: str = "openid email profile"
    oidc_auto_create: bool = True
    oidc_allowed_domains: str = ""
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
    # Per user and hour: manual scans and CVE searches that query NVD live.
    live_lookups_per_hour: int = 30
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

    @field_validator("database_url")
    @classmethod
    def _psycopg3(cls, value: str) -> str:
        # psycopg2 is no longer installed; psycopg 3 takes the same URLs.
        return value.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)

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

    @field_validator("public_url")
    @classmethod
    def _http_url(cls, value: Optional[str]) -> Optional[str]:
        if not value or not value.strip():
            return None
        value = value.strip().rstrip("/")
        if not value.startswith(("https://", "http://")):
            raise ValueError("PUBLIC_URL must start with https:// or http://")
        return value

    @field_validator("oidc_providers")
    @classmethod
    def _provider_ids(
        cls, value: dict[str, OidcProviderSettings]
    ) -> dict[str, OidcProviderSettings]:
        for provider_id in value:
            if not provider_id.replace("_", "").isalnum():
                raise ValueError(
                    f"OIDC provider id {provider_id!r} may only use letters, "
                    "digits and underscores"
                )
        return value

    @model_validator(mode="after")
    def _legacy_oidc_provider(self) -> "Settings":
        if (
            self.oidc_issuer
            and self.oidc_client_id
            and LEGACY_OIDC_PROVIDER not in self.oidc_providers
        ):
            self.oidc_providers[LEGACY_OIDC_PROVIDER] = OidcProviderSettings(
                issuer=self.oidc_issuer,
                client_id=self.oidc_client_id,
                client_secret=self.oidc_client_secret,
                discovery_url=self.oidc_discovery_url,
                name=self.oidc_provider_name,
                scopes=self.oidc_scopes,
                auto_create=self.oidc_auto_create,
                allowed_domains=self.oidc_allowed_domains,
            )
        return self

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
