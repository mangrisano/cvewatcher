"""Which account a verified provider identity signs in as."""

import re
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import User, UserIdentity
from app.services.oidc.client import OidcProvider
from app.services.oidc.errors import OidcError


def resolve_user(db: Session, provider: OidcProvider, claims: dict[str, Any]) -> User:
    """The account for a verified identity, linking or creating it as allowed."""
    subject = str(claims["sub"])
    user = _linked_user(db, provider.issuer, subject)
    if user is not None:
        return user

    email = _verified_email(provider, claims)
    user = db.query(User).filter(func.lower(User.email) == email).first()
    if user is None:
        if not provider.config.auto_create:
            raise OidcError("no_account")
        user = User(
            username=_unique_username(db, claims, email),
            email=email,
            password_hash=None,
        )
        db.add(user)
        db.flush()
    elif _has_identity_at(db, user, provider.issuer):
        # Another identity at the same provider already owns this account.
        raise OidcError("account_linked_elsewhere")

    user.email_verified = True  # type: ignore[assignment]
    db.add(UserIdentity(user_id=user.id, issuer=provider.issuer, subject=subject))
    db.commit()
    db.refresh(user)
    return user


def _linked_user(db: Session, issuer: str, subject: str) -> Optional[User]:
    return (
        db.query(User)
        .join(UserIdentity, UserIdentity.user_id == User.id)
        .filter(UserIdentity.issuer == issuer, UserIdentity.subject == subject)
        .first()
    )


def _has_identity_at(db: Session, user: User, issuer: str) -> bool:
    return (
        db.query(UserIdentity)
        .filter(UserIdentity.user_id == user.id, UserIdentity.issuer == issuer)
        .first()
        is not None
    )


def _verified_email(provider: OidcProvider, claims: dict[str, Any]) -> str:
    email = str(claims.get("email") or "").strip().lower()
    # An unverified address could belong to anyone: never match accounts on it.
    if not email or claims.get("email_verified") is not True:
        raise OidcError("email_not_verified")
    domains = provider.config.allowed_domain_set
    if domains and email.rsplit("@", 1)[-1] not in domains:
        raise OidcError("domain_not_allowed")
    return email


def _unique_username(db: Session, claims: dict[str, Any], email: str) -> str:
    wanted = claims.get("preferred_username") or email.split("@")[0]
    base = re.sub(r"[^A-Za-z0-9._-]", "", str(wanted))[:40] or "user"
    candidate, n = base, 1
    while db.query(User).filter(User.username == candidate).first() is not None:
        n += 1
        candidate = f"{base}{n}"
    return candidate
