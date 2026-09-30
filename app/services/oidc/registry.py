"""The providers configured in the settings, built once per settings object."""

from typing import Optional

from app.config import Settings, get_settings
from app.services.oidc.client import CALLBACK_PATH, OidcProvider

_cache: Optional[tuple[Settings, dict[str, OidcProvider]]] = None


def _build(settings: Settings) -> dict[str, OidcProvider]:
    # PUBLIC_URL builds the redirect URI registered with every provider.
    if not settings.public_url:
        return {}
    redirect_uri = f"{settings.public_url}{CALLBACK_PATH}"
    built = [
        OidcProvider(provider_id, config, redirect_uri)
        for provider_id, config in settings.oidc_providers.items()
    ]
    return {p.id: p for p in sorted(built, key=lambda p: p.name.lower())}


def providers() -> dict[str, OidcProvider]:
    """Every usable provider by id, ordered by name."""
    global _cache
    settings = get_settings()
    if _cache is None or _cache[0] is not settings:
        _cache = (settings, _build(settings))
    return _cache[1]


def get_provider(provider_id: str) -> Optional[OidcProvider]:
    return providers().get(provider_id)
