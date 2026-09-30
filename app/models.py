import datetime
import re
from enum import StrEnum
from uuid import UUID
from typing import Optional
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from app.services.notifications import (
    check_telegram_chat_id,
    check_telegram_token,
    check_webhook_url,
)


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain a lowercase letter")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain an uppercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain a digit")
    return password


class HealthResponse(BaseModel):
    status: str


class UserRegistrationRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_password_strength(password)


class UserLoginRequest(BaseModel):
    # No password rules here: a password that breaks them is just a wrong one
    # (401, counted by the rate limiter), and rules would reveal the policy.
    email: EmailStr
    password: str = Field(max_length=1024)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, password: str) -> str:
        return validate_password_strength(password)


class AssetCreate(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    ecosystem: Optional[str] = None
    description: Optional[str] = None


class AssetUpdate(BaseModel):
    """Partial update: only the fields sent are changed; null clears an optional one."""

    name: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    ecosystem: Optional[str] = None
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, name: Optional[str]) -> str:
        if name is None or not name.strip():
            raise ValueError("name cannot be empty")
        return name


class AssetResponse(BaseModel):
    id: UUID
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    ecosystem: Optional[str] = None
    user_email: str
    description: Optional[str] = None
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class SbomImportResponse(BaseModel):
    project: Optional[str] = None
    created: int
    skipped_existing: list[str]
    skipped_invalid: list[str]
    unsupported: list[str]


class VulnerabilityResponse(BaseModel):
    """A single CVE finding. The asset_* fields are populated when a finding is
    returned outside a per-asset envelope (e.g. by ``GET /cves/vulnerabilities``).
    """

    cve_id: str
    asset_id: Optional[UUID] = None
    asset_name: Optional[str] = None
    asset_version: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    summary: Optional[str] = None
    publish_date: Optional[str] = None
    modified_date: Optional[str] = None
    cve_url: Optional[str] = None
    relevance_reason: Optional[str] = None
    kev: bool = False
    epss: Optional[float] = None
    status: str = "open"


class AssetVulnerabilitiesResponse(BaseModel):
    asset: AssetResponse
    vulnerabilities: list[VulnerabilityResponse]
    total_vulnerabilities: int
    days_searched: int


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


# Statuses that take a finding out of the "active" set (hidden from the global
# view, counts, metrics and exports unless explicitly requested).
SUPPRESSED_STATUSES = frozenset(
    {
        FindingStatus.FIXED.value,
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.ACCEPTED_RISK.value,
    }
)


class FindingsSummary(BaseModel):
    """Counts cover every active finding; ``findings`` is one page of those
    matching the filters, ``matched`` how many match in total."""

    total: int
    kev: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    matched: int
    limit: int
    offset: int
    last_scan: Optional[datetime.datetime] = None
    unscanned_assets: int = 0
    total_assets: int = 0
    findings: list[VulnerabilityResponse]


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None


class FindingStatusResponse(BaseModel):
    asset_id: UUID
    cve_id: str
    status: FindingStatus
    notes: Optional[str] = None
    updated_at: Optional[datetime.datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AlertSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class NotificationSettings(BaseModel):
    """A user's alert settings. Webhook URLs are secrets: only their presence."""

    email: str
    email_available: bool
    min_severity: AlertSeverity
    always_kev: bool
    escalations: bool
    slack_configured: bool
    teams_configured: bool
    discord_configured: bool
    telegram_configured: bool


class NotificationSettingsUpdate(BaseModel):
    """Only the fields sent change; an empty webhook URL removes it.

    Telegram needs both the bot token and the chat id; sending either one empty
    removes Telegram.
    """

    min_severity: Optional[AlertSeverity] = None
    always_kev: Optional[bool] = None
    escalations: Optional[bool] = None
    slack_webhook_url: Optional[str] = Field(default=None, max_length=500)
    teams_webhook_url: Optional[str] = Field(default=None, max_length=500)
    discord_webhook_url: Optional[str] = Field(default=None, max_length=500)
    telegram_bot_token: Optional[str] = Field(default=None, max_length=100)
    telegram_chat_id: Optional[str] = Field(default=None, max_length=64)

    @field_validator("slack_webhook_url", "teams_webhook_url", "discord_webhook_url")
    @classmethod
    def _webhook(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        if not value or not value.strip():
            return value
        channel = (info.field_name or "").removesuffix("_webhook_url")
        return check_webhook_url(channel, value)

    @field_validator("telegram_bot_token")
    @classmethod
    def _telegram_token(cls, value: Optional[str]) -> Optional[str]:
        return check_telegram_token(value) if value and value.strip() else value

    @field_validator("telegram_chat_id")
    @classmethod
    def _telegram_chat(cls, value: Optional[str]) -> Optional[str]:
        return check_telegram_chat_id(value) if value and value.strip() else value

    @model_validator(mode="after")
    def _telegram_pair(self) -> "NotificationSettingsUpdate":
        token_set = bool(self.telegram_bot_token and self.telegram_bot_token.strip())
        chat_set = bool(self.telegram_chat_id and self.telegram_chat_id.strip())
        if token_set != chat_set:
            raise ValueError("Telegram needs both a bot token and a chat id")
        return self
