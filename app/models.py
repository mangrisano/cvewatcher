import datetime
import re
from uuid import UUID
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


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
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return password


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AssetCreate(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    description: Optional[str] = None


class AssetResponse(BaseModel):
    id: UUID
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    user_email: str
    description: Optional[str] = None
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


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


class AssetVulnerabilitiesResponse(BaseModel):
    asset: AssetResponse
    vulnerabilities: list[VulnerabilityResponse]
    total_vulnerabilities: int
    days_searched: int
