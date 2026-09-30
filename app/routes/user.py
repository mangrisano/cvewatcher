from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_current_user
from app.database import NotificationPreference, User, get_db
from app.models import (
    NotificationSettings,
    NotificationSettingsUpdate,
    PasswordChangeRequest,
)
from app.services.alerts import AlertPreferences, personal_notifiers
from app.services.notifications import send_email, smtp_config
from app.utils.auth import hash_password, issue_tokens, verify_password
from app.utils.rate_limit import InMemoryRateLimiter

router = APIRouter()

# Test messages hit external services: a few per user per hour is plenty.
_test_rate_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=3600)
# A stolen session must not be able to brute-force the current password.
_password_rate_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=900)

_SAMPLE_ALERT = {
    "alert": "test",
    "cve_id": "CVE-0000-0000",
    "severity": "CRITICAL",
    "score": 9.8,
    "asset_name": "cvewatcher",
    "asset_version": "test",
    "kev": True,
}


def _account(current_user: dict, db: Session) -> User:
    db_user = db.query(User).filter(User.email == current_user.get("sub")).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def _preferences_row(db: Session, user: User) -> Optional[NotificationPreference]:
    return db.get(NotificationPreference, user.id)


def _settings(
    user: User, row: Optional[NotificationPreference]
) -> NotificationSettings:
    prefs = AlertPreferences.from_row(row)
    return NotificationSettings(
        email=str(user.email),
        email_available=smtp_config() is not None,
        min_severity=prefs.min_severity,  # type: ignore[arg-type]
        always_kev=prefs.always_kev,
        escalations=prefs.escalations,
        slack_configured=prefs.slack_webhook_url is not None,
        teams_configured=prefs.teams_webhook_url is not None,
        discord_configured=prefs.discord_webhook_url is not None,
        telegram_configured=prefs.telegram_bot_token is not None
        and prefs.telegram_chat_id is not None,
    )


@router.get("/user", tags=["user"])
async def get_user_profile(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    db_user = _account(current_user, db)
    return {
        "id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "created_at": db_user.created_at,
    }


def _password_changed_notice(email: str) -> None:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    send_email(
        [email],
        "[CVE Watcher] Your password was changed",
        f"The password of your CVE Watcher account ({email}) was changed on "
        f"{when}.\nEvery other session has been signed out.\n\n"
        "If you did not do this, reset your password now and tell your "
        "administrator.",
    )


# A plain def: hashing 600k PBKDF2 rounds runs in the threadpool, off the loop.
@router.post("/user/password", tags=["user"])
def change_password(
    body: PasswordChangeRequest,
    background: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = _account(current_user, db)
    key = str(user.email).lower()
    retry_after = _password_rate_limiter.retry_after(key)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    # 400, not 401: the session is fine, and 401 would sign the client out.
    if not verify_password(body.current_password, str(user.password_hash)):
        _password_rate_limiter.record_failure(key)
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    _password_rate_limiter.reset(key)
    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=400,
            detail="The new password must differ from the current one",
        )

    user.password_hash = hash_password(body.new_password)  # type: ignore[assignment]
    # Signs out every session, this one included: it gets a fresh pair below.
    user.session_version = (user.session_version or 0) + 1  # type: ignore[assignment]
    db.commit()

    if smtp_config() is not None:
        background.add_task(_password_changed_notice, str(user.email))
    return {"message": "Password changed", **issue_tokens(user)}


@router.get("/user/notifications", response_model=NotificationSettings, tags=["user"])
async def get_notification_settings(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    user = _account(current_user, db)
    return _settings(user, _preferences_row(db, user))


@router.put("/user/notifications", response_model=NotificationSettings, tags=["user"])
async def update_notification_settings(
    update: NotificationSettingsUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = _account(current_user, db)
    row = _preferences_row(db, user)
    if row is None:
        row = NotificationPreference(user_id=user.id)
        db.add(row)
    for field in update.model_fields_set:
        value = getattr(update, field)
        if field.startswith("telegram_"):
            continue
        if field.endswith("_webhook_url"):
            setattr(row, field, value.strip() if value and value.strip() else None)
        elif value is not None:
            setattr(row, field, value)
    if update.model_fields_set & {"telegram_bot_token", "telegram_chat_id"}:
        # The validator guarantees both are set, or this removes Telegram.
        row.telegram_bot_token = update.telegram_bot_token or None  # type: ignore[assignment]
        row.telegram_chat_id = update.telegram_chat_id or None  # type: ignore[assignment]
    db.commit()
    db.refresh(row)
    return _settings(user, row)


@router.post("/user/notifications/test", tags=["user"])
async def send_test_notification(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
) -> dict[str, Any]:
    user = _account(current_user, db)
    key = str(user.email).lower()
    retry_after = _test_rate_limiter.retry_after(key)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Too many test notifications. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    prefs = AlertPreferences.from_row(_preferences_row(db, user))
    notifiers = personal_notifiers(str(user.email), prefs, smtp_config())
    if not notifiers:
        raise HTTPException(
            status_code=400, detail="No notification channel is configured"
        )
    _test_rate_limiter.record_failure(key)

    sample = {**_SAMPLE_ALERT, "user_email": user.email}
    results = {}
    for name, notifier in notifiers.items():
        try:
            results[name] = bool(await notifier.notify([sample]))
        except Exception:
            results[name] = False
    return {"results": results}
