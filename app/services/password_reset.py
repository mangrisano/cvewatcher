"""Password reset by email, and the notice sent when a password changes."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import PasswordResetToken, User
from app.services.notifications import send_email, smtp_config

RESET_TOKEN_TTL = timedelta(minutes=30)


def reset_available() -> bool:
    """Reset links need an SMTP relay and a trusted base URL for the link."""
    return smtp_config() is not None and get_settings().public_url is not None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_reset_token(db: Session, user: User) -> str:
    """A new single-use token for ``user``; older links of the user stop working."""
    now = datetime.now(timezone.utc)
    db.query(PasswordResetToken).filter(
        (PasswordResetToken.user_id == user.id) | (PasswordResetToken.expires_at <= now)
    ).delete(synchronize_session=False)
    token = secrets.token_urlsafe(32)
    db.add(
        PasswordResetToken(
            token_hash=_hash(token), user_id=user.id, expires_at=now + RESET_TOKEN_TTL
        )
    )
    db.commit()
    return token


def consume_reset_token(db: Session, token: str) -> Optional[User]:
    """The user a valid token belongs to, spending it; the caller commits."""
    token_hash = _hash(token)
    row = db.get(PasswordResetToken, token_hash)
    if row is None:
        return None
    user_id = row.user_id
    # A conditional delete claims the token, so two concurrent uses can't both win.
    claimed = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
        .delete(synchronize_session=False)
    )
    if not claimed:
        db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == token_hash
        ).delete(synchronize_session=False)
        db.commit()
        return None
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user_id).delete(
        synchronize_session=False
    )
    return db.get(User, user_id)


def send_reset_email(email: str, token: str) -> None:
    # The token goes in the fragment, which browsers never send to the server.
    link = f"{get_settings().public_url}/dashboard#reset={token}"
    minutes = int(RESET_TOKEN_TTL.total_seconds() // 60)
    send_email(
        [email],
        "[CVE Watcher] Reset your password",
        "Someone asked to reset the password of your CVE Watcher account "
        f"({email}).\n\nTo choose a new password, open this link within "
        f"{minutes} minutes:\n\n{link}\n\nIf you did not ask for this, ignore "
        "this email: your password stays the same.",
    )


def send_password_changed_notice(email: str) -> None:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    send_email(
        [email],
        "[CVE Watcher] Your password was changed",
        f"The password of your CVE Watcher account ({email}) was changed on "
        f"{when}.\nEvery other session has been signed out.\n\n"
        "If you did not do this, reset your password now and tell your "
        "administrator.",
    )
