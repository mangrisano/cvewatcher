from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from app.models import UserRegistrationRequest, UserLoginRequest, RefreshTokenRequest
from app.utils.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.utils.rate_limit import login_rate_limiter
from app.dependencies import get_current_user
from app.services.token_blocklist import revoke_token, is_token_revoked
from app.database import get_db, User

router = APIRouter()


@router.post("/auth/register", tags=["auth"])
async def register_user(user: UserRegistrationRequest, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter((User.email == user.email) | (User.username == user.username))
        .first()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username, email=user.email, password_hash=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {
        "message": f"User {user.username} registered successfully",
        "email": user.email,
    }


@router.post("/auth/login", tags=["auth"])
async def login_user(
    user: UserLoginRequest, request: Request, db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_key = f"{user.email.lower()}:{client_ip}"

    retry_after = login_rate_limiter.retry_after(rate_limit_key)
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user or not verify_password(user.password, str(db_user.password_hash)):
        login_rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_rate_limiter.reset(rate_limit_key)

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    return {
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
        },
    }


@router.post("/auth/refresh", tags=["auth"])
async def refresh_access_token(
    request: RefreshTokenRequest, db: Session = Depends(get_db)
):
    try:
        payload = verify_refresh_token(request.refresh_token)
        user_email = payload.get("sub")

        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if is_token_revoked(db, payload.get("jti")):
            raise HTTPException(
                status_code=401, detail="Refresh token has been revoked"
            )

        db_user = db.query(User).filter(User.email == user_email).first()
        if not db_user:
            raise HTTPException(status_code=401, detail="User not found")

        new_access_token = create_access_token(data={"sub": user_email})

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/auth/logout", tags=["auth"])
async def logout_user(
    body: Optional[RefreshTokenRequest] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    access_exp = current_user.get("exp")
    access_expires = (
        datetime.fromtimestamp(access_exp, tz=timezone.utc)
        if access_exp
        else datetime.now(timezone.utc)
    )
    revoke_token(db, current_user.get("jti"), access_expires)

    if body and body.refresh_token:
        try:
            refresh_payload = verify_refresh_token(body.refresh_token)
            refresh_exp = refresh_payload.get("exp")
            refresh_expires = (
                datetime.fromtimestamp(refresh_exp, tz=timezone.utc)
                if refresh_exp
                else datetime.now(timezone.utc)
            )
            revoke_token(db, refresh_payload.get("jti"), refresh_expires)
        except HTTPException:
            # An invalid or already-expired refresh token does not block logout.
            pass

    return {"message": "Logout successful. Tokens revoked."}
