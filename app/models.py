import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


class HealthResponse(BaseModel):
    status: str


class UserRegistrationRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return password


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return password


class AssetCreate(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    description: Optional[str] = None


class AssetResponse(BaseModel):
    id: int
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    user_email: str
    description: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True
