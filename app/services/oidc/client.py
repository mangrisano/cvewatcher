"""The OpenID Connect protocol against one provider (authorization code + PKCE)."""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet

from app.config import OidcProviderSettings
from app.services.oidc.errors import OidcError

CALLBACK_PATH = "/auth/oidc/callback"
# Asymmetric algorithms only: "none" and shared-secret HS* are never accepted.
_ALLOWED_ALGS = {
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512", "EdDSA",
}  # fmt: skip
_METADATA_TTL = 3600
_CLOCK_SKEW = 60
# Google's id_tokens may carry its issuer without the scheme.
_ISSUER_ALIASES = {"https://accounts.google.com": ["accounts.google.com"]}


def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10)


@dataclass
class LoginRequest:
    url: str
    state: str
    nonce: str
    verifier: str


@dataclass
class _Discovery:
    metadata: dict[str, Any]
    keys: KeySet
    fetched_at: float


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class OidcProvider:
    """One configured provider: its login URL and the checks on its answers."""

    def __init__(
        self, provider_id: str, config: OidcProviderSettings, redirect_uri: str
    ):
        self.id = provider_id
        self.name = config.name or provider_id.capitalize()
        self.config = config
        self.redirect_uri = redirect_uri
        self._discovery: Optional[_Discovery] = None

    @property
    def issuer(self) -> str:
        return self.config.issuer

    async def start_login(self) -> LoginRequest:
        discovery = await self._load()
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.config.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": self.config.scopes,
                "state": state,
                "nonce": nonce,
                "code_challenge": _pkce_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        url = f"{discovery.metadata['authorization_endpoint']}?{query}"
        return LoginRequest(url=url, state=state, nonce=nonce, verifier=verifier)

    async def finish_login(
        self, code: str, nonce: str, verifier: str
    ) -> dict[str, Any]:
        """The verified id_token claims for an authorization ``code``."""
        discovery = await self._load()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
            "client_id": self.config.client_id,
        }
        # Confidential clients authenticate with HTTP Basic; public ones rely on PKCE.
        extra: dict[str, Any] = {}
        if self.config.client_secret:
            extra["auth"] = httpx.BasicAuth(
                self.config.client_id, self.config.client_secret
            )
        try:
            async with http_client() as client:
                response = await client.post(
                    discovery.metadata["token_endpoint"], data=form, **extra
                )
                id_token = response.raise_for_status().json()["id_token"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise OidcError("token_exchange_failed") from e
        return await self._verify_id_token(id_token, nonce)

    async def _load(self, force: bool = False) -> _Discovery:
        cached = self._discovery
        if (
            cached is not None
            and not force
            and time.monotonic() - cached.fetched_at < _METADATA_TTL
        ):
            return cached
        url = (
            self.config.discovery_url
            or f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"
        )
        try:
            async with http_client() as client:
                metadata = (await client.get(url)).raise_for_status().json()
                jwks_response = await client.get(metadata["jwks_uri"])
                jwks = jwks_response.raise_for_status().json()
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise OidcError("provider_unavailable") from e
        # The discovery document must describe the issuer we were told to trust.
        if metadata.get("issuer") != self.issuer:
            raise OidcError("provider_unavailable")
        self._discovery = _Discovery(
            metadata, KeySet.import_key_set(jwks), time.monotonic()
        )
        return self._discovery

    async def _verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        discovery = await self._load()
        advertised = discovery.metadata.get("id_token_signing_alg_values_supported")
        algorithms = sorted(_ALLOWED_ALGS.intersection(advertised or ["RS256"]))
        issuers = [self.issuer, *_ISSUER_ALIASES.get(self.issuer, [])]
        try:
            try:
                decoded = jwt.decode(id_token, discovery.keys, algorithms=algorithms)
            except InvalidKeyIdError:
                # The provider rotated its keys since we cached them.
                discovery = await self._load(force=True)
                decoded = jwt.decode(id_token, discovery.keys, algorithms=algorithms)
            jwt.JWTClaimsRegistry(
                leeway=_CLOCK_SKEW,
                iss={"essential": True, "values": issuers},
                aud={"essential": True, "value": self.config.client_id},
                nonce={"essential": True, "value": nonce},
                sub={"essential": True},
                exp={"essential": True},
            ).validate(decoded.claims)
        except (JoseError, ValueError) as e:
            raise OidcError("invalid_id_token") from e
        return decoded.claims
