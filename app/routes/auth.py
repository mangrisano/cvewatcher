from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import (
    ForgotPasswordRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    UserLoginRequest,
    UserRegistrationRequest,
    VerifyEmailRequest,
)
from app.services.account_emails import (
    consume_reset_token,
    consume_verification_token,
    email_links_available,
    issue_reset_token,
    issue_verification_token,
    send_password_changed_notice,
    send_reset_email,
    send_verification_email,
)
from app.utils.auth import (
    hash_password,
    issue_tokens,
    password_needs_rehash,
    spend_password_check,
    token_matches_session,
    verify_password,
    verify_refresh_token,
)
from app.utils.rate_limit import (
    login_ip_rate_limiter,
    login_rate_limiter,
    registration_rate_limiter,
    reset_email_rate_limiter,
    reset_ip_rate_limiter,
)
from app.dependencies import get_current_user
from app.services.token_blocklist import (
    BlocklistUnavailableError,
    is_token_revoked,
    revoke_token,
)
from app.database import get_db, User
from app.config import get_settings

router = APIRouter()


def _expiry(claims: dict) -> datetime:
    exp = claims.get("exp")
    return (
        datetime.fromtimestamp(exp, tz=timezone.utc)
        if exp
        else datetime.now(timezone.utc)
    )


def _email_matches(email: str):
    # Emails identify users case-insensitively, so case variants can't coexist.
    return func.lower(User.email) == email.lower()


def _registration_open(db: Session) -> bool:
    # The first account can always be created (bootstrap); afterwards
    # registration must be explicitly enabled via REGISTRATION_ENABLED.
    if db.query(User).count() == 0:
        return True
    return get_settings().registration_enabled


@router.get("/auth/registration-status", tags=["auth"])
def registration_status(db: Session = Depends(get_db)):
    settings = get_settings()
    return {
        "open": _registration_open(db),
        "password_reset": email_links_available(),
        # The button label when single sign-on is configured, else None.
        "oidc": settings.oidc_provider_name if settings.oidc_enabled else None,
    }


def _limit_email_links(request: Request, email: str) -> None:
    """429 once an address or an IP asked for too many emailed links."""
    client_ip = request.client.host if request.client else "unknown"
    retry_after = max(
        reset_ip_rate_limiter.retry_after(client_ip),
        reset_email_rate_limiter.retry_after(email),
    )
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    reset_ip_rate_limiter.record_failure(client_ip)
    reset_email_rate_limiter.record_failure(email)


# Plain defs: hashing 600k PBKDF2 rounds runs in the threadpool, off the loop.
@router.post("/auth/register", tags=["auth"])
def register_user(
    user: UserRegistrationRequest,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not _registration_open(db):
        raise HTTPException(status_code=403, detail="Registration is disabled")

    client_ip = request.client.host if request.client else "unknown"
    retry_after = registration_rate_limiter.retry_after(client_ip)
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="Too many registration attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    registration_rate_limiter.record_failure(client_ip)

    email = user.email.lower()
    existing_user = (
        db.query(User)
        .filter((_email_matches(email)) | (User.username == user.username))
        .first()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    # With email set up, a new account stays inactive until its link is opened.
    verify = email_links_available()
    db_user = User(
        username=user.username,
        email=email,
        password_hash=hashed_password,
        email_verified=not verify,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if verify:
        token = issue_verification_token(db, db_user)
        background.add_task(send_verification_email, email, token)

    return {
        "message": f"User {user.username} registered successfully",
        "email": email,
        "verification_required": verify,
    }


@router.post("/auth/login", tags=["auth"])
def login_user(user: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_key = f"{user.email.lower()}:{client_ip}"

    retry_after = max(
        login_rate_limiter.retry_after(rate_limit_key),
        login_ip_rate_limiter.retry_after(client_ip),
    )
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    db_user = db.query(User).filter(_email_matches(user.email)).first()

    if db_user is None or db_user.password_hash is None:
        spend_password_check(user.password)
    if not db_user or not verify_password(user.password, str(db_user.password_hash)):
        login_rate_limiter.record_failure(rate_limit_key)
        login_ip_rate_limiter.record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # The per-IP counter is not reset: one valid account must not unlock spraying.
    login_rate_limiter.reset(rate_limit_key)

    # Checked after the password, so it can't reveal which addresses have accounts.
    # Without email set up there is no way to confirm, so the check is skipped.
    if not db_user.email_verified and email_links_available():
        raise HTTPException(
            status_code=403,
            detail="Confirm your email address first: check your inbox for the link.",
        )

    if password_needs_rehash(str(db_user.password_hash)):
        db_user.password_hash = hash_password(user.password)  # type: ignore[assignment]
        db.commit()

    return {
        "message": "Login successful",
        **issue_tokens(db_user),
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
        },
    }


@router.post("/auth/refresh", tags=["auth"])
def refresh_access_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
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
        if not token_matches_session(payload, db_user):
            raise HTTPException(
                status_code=401, detail="Session expired, please sign in again"
            )

        # Rotation: the presented refresh token is single-use.
        revoke_token(db, payload.get("jti"), _expiry(payload))

        return issue_tokens(db_user)

    except (HTTPException, BlocklistUnavailableError):
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/auth/logout", tags=["auth"])
def logout_user(
    body: Optional[RefreshTokenRequest] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    revoke_token(db, current_user.get("jti"), _expiry(current_user))

    if body and body.refresh_token:
        try:
            refresh_payload = verify_refresh_token(body.refresh_token)
            if refresh_payload.get("sub") == current_user.get("sub"):
                revoke_token(db, refresh_payload.get("jti"), _expiry(refresh_payload))
        except HTTPException:
            # An invalid or already-expired refresh token does not block logout.
            pass

    return {"message": "Logout successful. Tokens revoked."}


_RESET_SENT = {
    "message": "If an account exists for that email, a reset link is on its way."
}


@router.post("/auth/forgot-password", tags=["auth"])
def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not email_links_available():
        raise HTTPException(status_code=503, detail="Password reset is not available")

    email = body.email.lower()
    _limit_email_links(request, email)

    # Same answer whether or not the account exists; the email goes out after
    # the response, so the SMTP round-trip doesn't give it away either.
    db_user = db.query(User).filter(_email_matches(email)).first()
    if db_user is not None:
        token = issue_reset_token(db, db_user)
        background.add_task(send_reset_email, str(db_user.email), token)
    return _RESET_SENT


# A plain def: hashing 600k PBKDF2 rounds runs in the threadpool, off the loop.
@router.post("/auth/reset-password", tags=["auth"])
def reset_password(
    body: PasswordResetRequest,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    db_user = consume_reset_token(db, body.token)
    if db_user is None:
        raise HTTPException(
            status_code=400, detail="This reset link is invalid or has expired"
        )

    db_user.password_hash = hash_password(body.new_password)  # type: ignore[assignment]
    db_user.session_version = (db_user.session_version or 0) + 1  # type: ignore[assignment]
    # The link reached this inbox, which is what confirming the address proves.
    db_user.email_verified = True  # type: ignore[assignment]
    db.commit()

    client_ip = request.client.host if request.client else "unknown"
    login_rate_limiter.reset(f"{str(db_user.email).lower()}:{client_ip}")
    background.add_task(send_password_changed_notice, str(db_user.email))
    return {"message": "Password reset. You can now sign in."}


@router.post("/auth/verify-email", tags=["auth"])
def verify_email(body: VerifyEmailRequest, db: Session = Depends(get_db)):
    db_user = consume_verification_token(db, body.token)
    if db_user is None:
        raise HTTPException(
            status_code=400,
            detail="This confirmation link is invalid or has expired",
        )
    db_user.email_verified = True  # type: ignore[assignment]
    db.commit()
    return {"message": "Email confirmed. You can now sign in."}


_VERIFICATION_SENT = {
    "message": "If that account is waiting for confirmation, a new link is on its way."
}


@router.post("/auth/resend-verification", tags=["auth"])
def resend_verification(
    body: ForgotPasswordRequest,
    request: Request,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not email_links_available():
        raise HTTPException(status_code=503, detail="Email is not available")

    email = body.email.lower()
    _limit_email_links(request, email)

    db_user = db.query(User).filter(_email_matches(email)).first()
    if db_user is not None and not db_user.email_verified:
        token = issue_verification_token(db, db_user)
        background.add_task(send_verification_email, str(db_user.email), token)
    return _VERIFICATION_SENT
