import hmac
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.config import get_settings
from app.database import User, get_db
from app.models import OidcExchangeRequest
from app.services.oidc import (
    OidcError,
    OidcProvider,
    get_provider,
    providers,
    resolve_user,
)
from app.services.token_blocklist import is_token_revoked, revoke_token
from app.utils.auth import (
    issue_tokens,
    sign_short_lived,
    token_matches_session,
    verify_short_lived,
)

router = APIRouter()

# Holds state, nonce and the PKCE verifier between the redirect and the callback.
_COOKIE = "cvw_oidc"
_COOKIE_PATH = "/auth/oidc"
_LOGIN_SECONDS = 600
_HANDOFF_SECONDS = 60
# Dropping <name>.svg here gives every provider using that icon its logo.
_ICONS_DIR = Path(__file__).resolve().parent.parent / "static" / "img" / "providers"


def _icon_url(provider: OidcProvider) -> Optional[str]:
    name = provider.config.icon or provider.id
    if (_ICONS_DIR / f"{name}.svg").is_file():
        return f"/static/img/providers/{name}.svg"
    return None


def public_providers() -> list[dict[str, Optional[str]]]:
    """What the login page needs to draw one button per provider."""
    return [
        {"id": p.id, "name": p.name, "icon": _icon_url(p)} for p in providers().values()
    ]


def _provider(provider_id: str | None) -> OidcProvider:
    """The provider asked for; the only one when there is just one."""
    configured = providers()
    if provider_id is None and len(configured) == 1:
        return next(iter(configured.values()))
    provider = get_provider(provider_id or "")
    if provider is None:
        raise HTTPException(status_code=404, detail="Unknown sign-in provider")
    return provider


def _to_dashboard(fragment: str) -> RedirectResponse:
    # A fragment is never sent to the server, so it stays out of access logs.
    return RedirectResponse(
        f"{get_settings().public_url}/dashboard#{fragment}", status_code=302
    )


@router.get("/auth/oidc/login", tags=["auth"])
async def oidc_login(provider: str | None = None):
    selected = _provider(provider)
    try:
        login = await selected.start_login()
    except OidcError as e:
        return _to_dashboard(f"oidc_error={e.code}")
    pending = sign_short_lived(
        {
            "p": selected.id,
            "state": login.state,
            "nonce": login.nonce,
            "cv": login.verifier,
        },
        "oidc_login",
        _LOGIN_SECONDS,
    )
    response = RedirectResponse(login.url, status_code=302)
    response.set_cookie(
        _COOKIE,
        pending,
        max_age=_LOGIN_SECONDS,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=str(get_settings().public_url).startswith("https://"),
    )
    return response


@router.get("/auth/oidc/callback", tags=["auth"])
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    pending = verify_short_lived(request.cookies.get(_COOKIE, ""), "oidc_login")
    try:
        if error:
            raise OidcError("provider_refused")
        # The state must come back to the same browser that started the login.
        if not (pending and code and state) or not hmac.compare_digest(
            state, str(pending["state"])
        ):
            raise OidcError("invalid_state")
        provider = get_provider(str(pending.get("p")))
        if provider is None:
            raise OidcError("invalid_state")
        claims = await provider.finish_login(code, pending["nonce"], pending["cv"])
        user = await run_in_threadpool(resolve_user, db, provider, claims)
        handoff = sign_short_lived(
            {"sub": user.email, "ver": user.session_version or 0},
            "oidc_handoff",
            _HANDOFF_SECONDS,
        )
        response = _to_dashboard(f"oidc={handoff}")
    except OidcError as e:
        response = _to_dashboard(f"oidc_error={e.code}")
    response.delete_cookie(_COOKIE, path=_COOKIE_PATH)
    return response


@router.post("/auth/oidc/exchange", tags=["auth"])
def oidc_exchange(body: OidcExchangeRequest, db: Session = Depends(get_db)):
    """Trade the one-time code from the callback for a session."""
    claims = verify_short_lived(body.code, "oidc_handoff")
    if claims is None or is_token_revoked(db, claims.get("jti")):
        raise HTTPException(status_code=400, detail="This sign-in link has expired")
    revoke_token(
        db, claims.get("jti"), datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    )
    user = db.query(User).filter(User.email == claims.get("sub")).first()
    if user is None or not token_matches_session(claims, user):
        raise HTTPException(status_code=400, detail="This sign-in link has expired")
    return {
        "message": "Login successful",
        **issue_tokens(user),
        "user": {"id": user.id, "username": user.username, "email": user.email},
    }
