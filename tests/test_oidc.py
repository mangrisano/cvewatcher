"""Single sign-on through OpenID Connect, against a fake identity provider."""

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from app.config import get_settings
from app.database.connection import SessionLocal
from app.database.models import User
from app.services import oidc

ISSUER = "https://idp.test/realms/cvw"
CLIENT_ID = "cvewatcher"
SECRET = "client-secret"
PUBLIC_URL = "http://cvw.test"


class FakeIdP:
    """Discovery, JWKS and token endpoints, signing real RS256 id_tokens."""

    def __init__(self):
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1"}, private=True)
        self.pending: dict[str, dict] = {}
        self.issuer = ISSUER
        self.overrides: dict = {}
        self.signing_key = None
        self.header: dict = {}

    def authorize(self, location: str, **claims) -> tuple[str, str]:
        """Approve the login the app redirected to; returns (code, state)."""
        query = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
        assert query["client_id"] == CLIENT_ID
        assert query["code_challenge_method"] == "S256"
        code = f"code-{len(self.pending)}"
        self.pending[code] = {
            "challenge": query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
            "claims": {
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "sub": "alice-id",
                "nonce": query["nonce"],
                "email": "alice@example.com",
                "email_verified": True,
                "preferred_username": "alice",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
                **claims,
            },
        }
        return code, query["state"]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": self.issuer,
                    "authorization_endpoint": f"{ISSUER}/auth",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/certs",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            credentials = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if request.headers.get("authorization") != f"Basic {credentials}":
                return httpx.Response(401, json={"error": "invalid_client"})
            grant = self.pending.pop(form.get("code", ""), None)
            if grant is None or form["redirect_uri"] != grant["redirect_uri"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            digest = hashlib.sha256(form["code_verifier"].encode()).digest()
            if (
                base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                != grant["challenge"]
            ):
                return httpx.Response(400, json={"error": "invalid_grant"})
            claims = {**grant["claims"], **self.overrides}
            header = {"alg": "RS256", "kid": "k1", **self.header}
            token = jwt.encode(header, claims, self.signing_key or self.key)
            return httpx.Response(200, json={"id_token": token})
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("OIDC_PROVIDER_NAME", "Keycloak")
    monkeypatch.setenv("PUBLIC_URL", PUBLIC_URL)
    get_settings.cache_clear()
    monkeypatch.setattr(oidc, "_provider", None)
    monkeypatch.setattr(
        oidc,
        "_http",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    yield fake


def _sign_in(client, idp, **claims) -> str:
    """Run the redirect dance; returns the fragment of the final dashboard URL."""
    start = client.get("/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302
    code, state = idp.authorize(start.headers["location"], **claims)
    back = client.get(
        f"/auth/oidc/callback?code={code}&state={state}", follow_redirects=False
    )
    assert back.status_code == 302
    location = back.headers["location"]
    assert location.startswith(f"{PUBLIC_URL}/dashboard#")
    return location.split("#", 1)[1]


def _exchange(client, fragment):
    assert fragment.startswith("oidc="), fragment
    return client.post("/auth/oidc/exchange", json={"code": fragment[len("oidc=") :]})


def _user(email):
    with SessionLocal() as db:
        return db.query(User).filter(User.email == email).first()


def _cleanup(*emails):
    with SessionLocal() as db:
        db.query(User).filter(User.email.in_(emails)).delete()
        db.commit()


def test_status_shows_the_provider_only_when_configured(client, idp, monkeypatch):
    assert client.get("/auth/registration-status").json()["oidc"] == "Keycloak"
    monkeypatch.delenv("OIDC_ISSUER")
    get_settings.cache_clear()
    assert client.get("/auth/registration-status").json()["oidc"] is None
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 404


def test_first_sign_in_creates_a_password_less_account(client, idp):
    response = _exchange(client, _sign_in(client, idp))
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    profile = client.get("/user", headers=headers).json()
    assert profile["email"] == "alice@example.com"
    assert profile["username"] == "alice"
    assert profile["has_password"] is False and profile["sso"] is True

    # Password sign-in can't be used on an account without a password.
    login = client.post(
        "/auth/login", json={"email": "alice@example.com", "password": "Password123"}
    )
    assert login.status_code == 401

    # The next sign-in finds the same account by its provider identity.
    assert (
        _exchange(client, _sign_in(client, idp, email="new@example.com")).status_code
        == 200
    )
    assert _user("new@example.com") is None
    _cleanup("alice@example.com")


def test_the_handoff_code_works_once(client, idp):
    fragment = _sign_in(client, idp, sub="once-id", email="once@example.com")
    assert _exchange(client, fragment).status_code == 200
    assert _exchange(client, fragment).status_code == 400
    _cleanup("once@example.com")


def test_an_existing_account_is_linked_by_verified_email(client, idp):
    client.post(
        "/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": "Password123"},
    )
    fragment = _sign_in(client, idp, sub="bob-id", email="bob@example.com")
    assert _exchange(client, fragment).status_code == 200
    user = _user("bob@example.com")
    assert user is not None and user.oidc_subject == "bob-id"
    # The password keeps working alongside single sign-on.
    login = client.post(
        "/auth/login", json={"email": "bob@example.com", "password": "Password123"}
    )
    assert login.status_code == 200
    _cleanup("bob@example.com")


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        (
            {"email_verified": False, "sub": "u1", "email": "u1@example.com"},
            "email_not_verified",
        ),
        ({"email": None, "sub": "u2"}, "email_not_verified"),
    ],
)
def test_unverified_emails_are_refused(client, idp, claims, error):
    assert _sign_in(client, idp, **claims) == f"oidc_error={error}"


def test_only_allowed_domains_get_in(client, idp, monkeypatch):
    monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "corp.example")
    get_settings.cache_clear()
    fragment = _sign_in(client, idp, sub="out-id", email="out@example.com")
    assert fragment == "oidc_error=domain_not_allowed"
    fragment = _sign_in(client, idp, sub="in-id", email="in@corp.example")
    assert _exchange(client, fragment).status_code == 200
    _cleanup("in@corp.example")


def test_no_account_is_created_when_auto_create_is_off(client, idp, monkeypatch):
    monkeypatch.setenv("OIDC_AUTO_CREATE", "false")
    get_settings.cache_clear()
    fragment = _sign_in(client, idp, sub="nobody-id", email="nobody-oidc@example.com")
    assert fragment == "oidc_error=no_account"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "https://evil.test"},
        {"nonce": "replayed"},
        {"exp": int(time.time()) - 3600},
    ],
)
def test_bad_id_tokens_are_refused(client, idp, overrides):
    idp.overrides = overrides
    fragment = _sign_in(client, idp, sub="bad-id", email="bad@example.com")
    assert fragment == "oidc_error=invalid_id_token"
    assert _user("bad@example.com") is None


def test_a_token_signed_with_a_shared_secret_is_refused(client, idp):
    # Algorithm confusion: an HS256 token keyed with public material must not pass.
    idp.signing_key = OctKey.import_key("x" * 32)
    idp.header = {"alg": "HS256"}
    fragment = _sign_in(client, idp, sub="hs-id", email="hs@example.com")
    assert fragment == "oidc_error=invalid_id_token"


def test_rotated_provider_keys_are_fetched_again(client, idp):
    _sign_in(client, idp, sub="rot1-id", email="rot1@example.com")
    idp.key = RSAKey.generate_key(2048, parameters={"kid": "k2"}, private=True)
    idp.header = {"kid": "k2"}
    fragment = _sign_in(client, idp, sub="rot2-id", email="rot2@example.com")
    assert _exchange(client, fragment).status_code == 200
    _cleanup("rot1@example.com", "rot2@example.com")


def test_the_state_must_match_the_browser_that_started(client, idp):
    start = client.get("/auth/oidc/login", follow_redirects=False)
    code, _ = idp.authorize(start.headers["location"])
    back = client.get(
        f"/auth/oidc/callback?code={code}&state=forged", follow_redirects=False
    )
    assert back.headers["location"].endswith("#oidc_error=invalid_state")

    # A callback from another browser (no login cookie) fails too.
    start = client.get("/auth/oidc/login", follow_redirects=False)
    code, state = idp.authorize(start.headers["location"])
    client.cookies.clear()
    back = client.get(
        f"/auth/oidc/callback?code={code}&state={state}", follow_redirects=False
    )
    assert back.headers["location"].endswith("#oidc_error=invalid_state")


def test_a_refusal_at_the_provider_is_reported(client, idp):
    back = client.get(
        "/auth/oidc/callback?error=access_denied&state=x", follow_redirects=False
    )
    assert back.headers["location"].endswith("#oidc_error=provider_refused")


def test_a_discovery_document_for_another_issuer_is_refused(client, idp):
    idp.issuer = "https://evil.test"
    start = client.get("/auth/oidc/login", follow_redirects=False)
    assert start.headers["location"].endswith("#oidc_error=provider_unavailable")


def test_single_sign_on_accounts_confirm_deletion_with_their_email(client, idp):
    response = _exchange(
        client, _sign_in(client, idp, sub="del-id", email="del@example.com")
    )
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    wrong = client.request(
        "DELETE", "/user", json={"confirm_email": "x@example.com"}, headers=headers
    )
    assert wrong.status_code == 400
    ok = client.request(
        "DELETE", "/user", json={"confirm_email": "DEL@example.com"}, headers=headers
    )
    assert ok.status_code == 200
    assert _user("del@example.com") is None
