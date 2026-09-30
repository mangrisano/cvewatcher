"""Single sign-on through OpenID Connect, against fake identity providers."""

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
from app.database.models import User, UserIdentity
from app.services.oidc import client as oidc_client

ISSUER = "https://idp.test/realms/cvw"
GOOGLE = "https://accounts.google.com"
CLIENT_ID = "cvewatcher"
SECRET = "client-secret"
PUBLIC_URL = "http://cvw.test"


class FakeIdP:
    """Discovery, JWKS and token endpoints, signing real RS256 id_tokens."""

    def __init__(self, issuer: str = ISSUER):
        self.issuer = issuer
        # What the discovery document claims; tests may make it lie.
        self.advertised_issuer = issuer
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1"}, private=True)
        self.pending: dict[str, dict] = {}
        self.overrides: dict = {}
        self.signing_key = None
        self.header: dict = {}

    def authorize(self, location: str, **claims) -> tuple[str, str]:
        """Approve the login the app redirected to; returns (code, state)."""
        query = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
        assert location.startswith(f"{self.issuer}/auth?")
        assert query["client_id"] == CLIENT_ID
        assert query["code_challenge_method"] == "S256"
        code = f"code-{len(self.pending)}"
        self.pending[code] = {
            "challenge": query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
            "claims": {
                "iss": self.issuer,
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

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": self.advertised_issuer,
                    "authorization_endpoint": f"{self.issuer}/auth",
                    "token_endpoint": f"{self.issuer}/token",
                    "jwks_uri": f"{self.issuer}/certs",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if path.endswith("/token"):
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        credentials = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
        if request.headers.get("authorization") != f"Basic {credentials}":
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.pending.pop(form.get("code", ""), None)
        if grant is None or form["redirect_uri"] != grant["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        digest = hashlib.sha256(form["code_verifier"].encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != grant["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        claims = {**grant["claims"], **self.overrides}
        header = {"alg": "RS256", "kid": "k1", **self.header}
        token = jwt.encode(header, claims, self.signing_key or self.key)
        return httpx.Response(200, json={"id_token": token})


class FakeProviders:
    """Configures providers through the environment and serves them all."""

    def __init__(self, monkeypatch):
        self._monkeypatch = monkeypatch
        self._by_host: dict[str, FakeIdP] = {}
        monkeypatch.setenv("PUBLIC_URL", PUBLIC_URL)
        monkeypatch.setattr(
            oidc_client,
            "http_client",
            lambda: httpx.AsyncClient(transport=httpx.MockTransport(self._route)),
        )

    def add(self, provider_id: str, issuer: str = ISSUER, **settings) -> FakeIdP:
        idp = self.serve(issuer)
        values = {"issuer": issuer, "client_id": CLIENT_ID, "client_secret": SECRET}
        for field, value in {**values, **settings}.items():
            self.set(provider_id, field, value)
        return idp

    def serve(self, issuer: str) -> FakeIdP:
        idp = FakeIdP(issuer)
        self._by_host[urlparse(issuer).netloc] = idp
        return idp

    def set(self, provider_id: str, field: str, value: str) -> None:
        name = f"OIDC_PROVIDERS__{provider_id.upper()}__{field.upper()}"
        self._monkeypatch.setenv(name, value)
        get_settings.cache_clear()

    def _route(self, request: httpx.Request) -> httpx.Response:
        return self._by_host[request.url.host].handle(request)


@pytest.fixture
def idps(monkeypatch):
    return FakeProviders(monkeypatch)


@pytest.fixture
def idp(idps):
    return idps.add("keycloak")


def _sign_in(client, idp, provider=None, **claims) -> str:
    """Run the redirect dance; returns the fragment of the final dashboard URL."""
    query = f"?provider={provider}" if provider else ""
    start = client.get(f"/auth/oidc/login{query}", follow_redirects=False)
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


def _identities(email) -> set[tuple[str, str]]:
    with SessionLocal() as db:
        rows = (
            db.query(UserIdentity.issuer, UserIdentity.subject)
            .join(User, User.id == UserIdentity.user_id)
            .filter(User.email == email)
        )
        return {(issuer, subject) for issuer, subject in rows}


def _cleanup(*emails):
    with SessionLocal() as db:
        for user in db.query(User).filter(User.email.in_(emails)):
            db.delete(user)
        db.commit()


def test_status_lists_the_configured_providers(client, idps):
    assert client.get("/auth/registration-status").json()["oidc"] == []
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 404

    idps.add("keycloak")
    idps.add("google", GOOGLE)
    assert client.get("/auth/registration-status").json()["oidc"] == [
        {"id": "google", "name": "Google", "icon": "/static/img/providers/google.svg"},
        {
            "id": "keycloak",
            "name": "Keycloak",
            "icon": "/static/img/providers/keycloak.svg",
        },
    ]
    idps.set("keycloak", "name", "Company SSO")
    names = [p["name"] for p in client.get("/auth/registration-status").json()["oidc"]]
    assert names == ["Company SSO", "Google"]


def test_icons_come_from_the_id_or_the_icon_setting(client, idps):
    idps.add("corp")
    idps.add("workspace", GOOGLE, icon="google")
    icons = {
        p["id"]: p["icon"]
        for p in client.get("/auth/registration-status").json()["oidc"]
    }
    assert icons == {"corp": None, "workspace": "/static/img/providers/google.svg"}
    assert client.get(icons["workspace"]).headers["content-type"] == "image/svg+xml"


def test_icon_names_cannot_leave_the_icons_folder(monkeypatch, idps):
    idps.add("corp", icon="../../main")
    with pytest.raises(ValueError, match="icon name"):
        get_settings()


def test_providers_need_the_public_url(client, idp, monkeypatch):
    monkeypatch.delenv("PUBLIC_URL")
    get_settings.cache_clear()
    assert client.get("/auth/registration-status").json()["oidc"] == []


def test_the_provider_must_be_chosen_when_there_are_several(client, idps):
    idps.add("keycloak")
    google = idps.add("google", GOOGLE)
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 404
    assert (
        client.get("/auth/oidc/login?provider=nope", follow_redirects=False).status_code
        == 404
    )
    fragment = _sign_in(client, google, "google", sub="g-1", email="gsel@example.com")
    assert _exchange(client, fragment).status_code == 200
    assert _identities("gsel@example.com") == {(GOOGLE, "g-1")}
    _cleanup("gsel@example.com")


def test_one_account_can_sign_in_with_several_providers(client, idps):
    keycloak = idps.add("keycloak")
    google = idps.add("google", GOOGLE)
    email = "multi@example.com"
    first = _sign_in(client, keycloak, "keycloak", sub="kc-1", email=email)
    assert _exchange(client, first).status_code == 200
    second = _sign_in(client, google, "google", sub="g-1", email=email)
    assert _exchange(client, second).status_code == 200
    assert _identities(email) == {(ISSUER, "kc-1"), (GOOGLE, "g-1")}

    # Either identity now signs in, even after the provider changes the email.
    again = _sign_in(client, google, "google", sub="g-1", email="renamed@example.com")
    assert _exchange(client, again).json()["user"]["email"] == email
    assert _user("renamed@example.com") is None
    _cleanup(email)


def test_settings_are_per_provider(client, idps):
    keycloak = idps.add("keycloak")
    google = idps.add("google", GOOGLE, allowed_domains="corp.example")
    fragment = _sign_in(client, google, "google", sub="g-out", email="o@example.com")
    assert fragment == "oidc_error=domain_not_allowed"
    fragment = _sign_in(client, keycloak, "keycloak", sub="kc-o", email="o@example.com")
    assert _exchange(client, fragment).status_code == 200
    _cleanup("o@example.com")


def test_the_single_provider_variables_still_work(client, idps, monkeypatch):
    idp = idps.serve(ISSUER)
    for name, value in {
        "OIDC_ISSUER": ISSUER,
        "OIDC_CLIENT_ID": CLIENT_ID,
        "OIDC_CLIENT_SECRET": SECRET,
        "OIDC_PROVIDER_NAME": "Legacy SSO",
    }.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    assert client.get("/auth/registration-status").json()["oidc"] == [
        {"id": "default", "name": "Legacy SSO", "icon": None}
    ]
    fragment = _sign_in(client, idp, sub="legacy-id", email="legacy@example.com")
    assert _exchange(client, fragment).status_code == 200
    _cleanup("legacy@example.com")


def test_invalid_provider_ids_fail_at_startup(monkeypatch):
    monkeypatch.setenv("OIDC_PROVIDERS__MY-IDP__ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_PROVIDERS__MY-IDP__CLIENT_ID", CLIENT_ID)
    get_settings.cache_clear()
    with pytest.raises(ValueError, match="letters, digits and underscores"):
        get_settings()


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
    assert _identities("bob@example.com") == {(ISSUER, "bob-id")}
    # The password keeps working alongside single sign-on.
    login = client.post(
        "/auth/login", json={"email": "bob@example.com", "password": "Password123"}
    )
    assert login.status_code == 200
    _cleanup("bob@example.com")


def test_a_second_identity_at_the_same_provider_is_refused(client, idp):
    first = _sign_in(client, idp, sub="first-id", email="same@example.com")
    assert _exchange(client, first).status_code == 200
    second = _sign_in(client, idp, sub="other-id", email="same@example.com")
    assert second == "oidc_error=account_linked_elsewhere"
    _cleanup("same@example.com")


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


def test_only_allowed_domains_get_in(client, idps):
    idp = idps.add("keycloak", allowed_domains="corp.example")
    fragment = _sign_in(client, idp, sub="out-id", email="out@example.com")
    assert fragment == "oidc_error=domain_not_allowed"
    fragment = _sign_in(client, idp, sub="in-id", email="in@corp.example")
    assert _exchange(client, fragment).status_code == 200
    _cleanup("in@corp.example")


def test_no_account_is_created_when_auto_create_is_off(client, idps):
    idp = idps.add("keycloak", auto_create="false")
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


def test_an_id_token_from_another_configured_provider_is_refused(client, idps):
    idps.add("keycloak")
    google = idps.add("google", GOOGLE)
    google.overrides = {"iss": ISSUER}
    fragment = _sign_in(client, google, "google", sub="x-id", email="x@example.com")
    assert fragment == "oidc_error=invalid_id_token"


def test_google_issuer_without_scheme_is_accepted(client, idps):
    google = idps.add("google", GOOGLE)
    google.overrides = {"iss": "accounts.google.com"}
    fragment = _sign_in(client, google, sub="g-id", email="g@example.com")
    assert _exchange(client, fragment).status_code == 200
    assert _identities("g@example.com") == {(GOOGLE, "g-id")}
    _cleanup("g@example.com")


def test_other_issuers_have_no_scheme_less_form(client, idp):
    idp.overrides = {"iss": ISSUER.removeprefix("https://")}
    fragment = _sign_in(client, idp, sub="ns-id", email="ns@example.com")
    assert fragment == "oidc_error=invalid_id_token"


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


def test_a_provider_removed_mid_login_is_refused(client, idps, monkeypatch):
    idps.add("keycloak")
    google = idps.add("google", GOOGLE)
    start = client.get("/auth/oidc/login?provider=google", follow_redirects=False)
    code, state = google.authorize(start.headers["location"])
    monkeypatch.delenv("OIDC_PROVIDERS__GOOGLE__ISSUER")
    monkeypatch.delenv("OIDC_PROVIDERS__GOOGLE__CLIENT_ID")
    monkeypatch.delenv("OIDC_PROVIDERS__GOOGLE__CLIENT_SECRET")
    get_settings.cache_clear()
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
    idp.advertised_issuer = "https://evil.test"
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
    with SessionLocal() as db:
        assert db.query(UserIdentity).filter_by(subject="del-id").count() == 0
