"""Sign-in through an OpenID Connect provider (authorization code flow + PKCE)."""

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import User

CALLBACK_PATH = "/auth/oidc/callback"
# Asymmetric algorithms only: "none" and shared-secret HS* are never accepted.
_ALLOWED_ALGS = {
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512", "EdDSA",
}  # fmt: skip
_METADATA_TTL = 3600
_CLOCK_SKEW = 60


class OidcError(Exception):
    """A failed sign-in; ``code`` is shown to the user, never provider details."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class _Provider:
    metadata: dict[str, Any]
    keys: KeySet
    fetched_at: float


_provider: Optional[_Provider] = None


def _http() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10)


def redirect_uri() -> str:
    return f"{get_settings().public_url}{CALLBACK_PATH}"


async def _load_provider(force: bool = False) -> _Provider:
    global _provider
    if (
        _provider is not None
        and not force
        and time.monotonic() - _provider.fetched_at < _METADATA_TTL
    ):
        return _provider
    settings = get_settings()
    issuer = str(settings.oidc_issuer)
    url = (
        settings.oidc_discovery_url
        or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    )
    try:
        async with _http() as client:
            metadata = (await client.get(url)).raise_for_status().json()
            jwks = (await client.get(metadata["jwks_uri"])).raise_for_status().json()
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise OidcError("provider_unavailable") from e
    # The discovery document must describe the issuer we were told to trust.
    if metadata.get("issuer") != issuer:
        raise OidcError("provider_unavailable")
    _provider = _Provider(metadata, KeySet.import_key_set(jwks), time.monotonic())
    return _provider


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class LoginRequest:
    url: str
    state: str
    nonce: str
    verifier: str


async def start_login() -> LoginRequest:
    settings = get_settings()
    provider = await _load_provider()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": redirect_uri(),
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    url = f"{provider.metadata['authorization_endpoint']}?{query}"
    return LoginRequest(url=url, state=state, nonce=nonce, verifier=verifier)


async def finish_login(code: str, nonce: str, verifier: str) -> dict[str, Any]:
    """The verified id_token claims for an authorization ``code``."""
    settings = get_settings()
    provider = await _load_provider()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "code_verifier": verifier,
        "client_id": settings.oidc_client_id,
    }
    # Confidential clients authenticate with HTTP Basic; public ones rely on PKCE.
    extra: dict[str, Any] = {}
    if settings.oidc_client_secret:
        extra["auth"] = httpx.BasicAuth(
            str(settings.oidc_client_id), settings.oidc_client_secret
        )
    try:
        async with _http() as client:
            response = await client.post(
                provider.metadata["token_endpoint"], data=form, **extra
            )
            id_token = response.raise_for_status().json()["id_token"]
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise OidcError("token_exchange_failed") from e
    return await _verify_id_token(id_token, nonce)


async def _verify_id_token(id_token: str, nonce: str) -> dict[str, Any]:
    settings = get_settings()
    provider = await _load_provider()
    advertised = provider.metadata.get("id_token_signing_alg_values_supported")
    algorithms = sorted(_ALLOWED_ALGS.intersection(advertised or ["RS256"]))
    try:
        try:
            decoded = jwt.decode(id_token, provider.keys, algorithms=algorithms)
        except InvalidKeyIdError:
            # The provider rotated its keys since we cached them.
            provider = await _load_provider(force=True)
            decoded = jwt.decode(id_token, provider.keys, algorithms=algorithms)
        jwt.JWTClaimsRegistry(
            leeway=_CLOCK_SKEW,
            iss={"essential": True, "value": str(settings.oidc_issuer)},
            aud={"essential": True, "value": str(settings.oidc_client_id)},
            nonce={"essential": True, "value": nonce},
            sub={"essential": True},
            exp={"essential": True},
        ).validate(decoded.claims)
    except (JoseError, ValueError) as e:
        raise OidcError("invalid_id_token") from e
    return decoded.claims


def _unique_username(db: Session, claims: dict[str, Any], email: str) -> str:
    wanted = claims.get("preferred_username") or email.split("@")[0]
    base = re.sub(r"[^A-Za-z0-9._-]", "", str(wanted))[:40] or "user"
    candidate, n = base, 1
    while db.query(User).filter(User.username == candidate).first() is not None:
        n += 1
        candidate = f"{base}{n}"
    return candidate


def resolve_user(db: Session, claims: dict[str, Any]) -> User:
    """The account for a verified identity, linking or creating it as allowed."""
    settings = get_settings()
    issuer, subject = str(settings.oidc_issuer), str(claims["sub"])
    user = (
        db.query(User)
        .filter(User.oidc_issuer == issuer, User.oidc_subject == subject)
        .first()
    )
    if user is not None:
        return user

    email = str(claims.get("email") or "").strip().lower()
    # An unverified address could belong to anyone: never match accounts on it.
    if not email or claims.get("email_verified") is not True:
        raise OidcError("email_not_verified")
    domains = settings.oidc_allowed_domain_set
    if domains and email.rsplit("@", 1)[-1] not in domains:
        raise OidcError("domain_not_allowed")

    user = db.query(User).filter(func.lower(User.email) == email).first()
    if user is not None:
        if user.oidc_subject is not None:
            raise OidcError("account_linked_elsewhere")
        user.oidc_issuer = issuer  # type: ignore[assignment]
        user.oidc_subject = subject  # type: ignore[assignment]
        user.email_verified = True  # type: ignore[assignment]
        db.commit()
        return user

    if not settings.oidc_auto_create:
        raise OidcError("no_account")
    user = User(
        username=_unique_username(db, claims, email),
        email=email,
        password_hash=None,
        email_verified=True,
        oidc_issuer=issuer,
        oidc_subject=subject,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
