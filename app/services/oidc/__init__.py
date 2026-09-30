"""Single sign-on through any number of OpenID Connect providers."""

from app.services.oidc.accounts import resolve_user
from app.services.oidc.client import CALLBACK_PATH, LoginRequest, OidcProvider
from app.services.oidc.errors import OidcError
from app.services.oidc.registry import get_provider, providers

__all__ = [
    "CALLBACK_PATH",
    "LoginRequest",
    "OidcError",
    "OidcProvider",
    "get_provider",
    "providers",
    "resolve_user",
]
