"""Forgot password: reset links sent by email."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.config import get_settings
from app.database.connection import SessionLocal
from app.database.models import PasswordResetToken
from app.routes import auth as auth_routes
from app.services import password_reset
from app.utils.rate_limit import reset_ip_rate_limiter

PASSWORD = "Password123"
NEW_PASSWORD = "NewPassword456"


@pytest.fixture
def reset_on(monkeypatch):
    """Reset enabled; returns the (email, token) pairs that would be emailed."""
    monkeypatch.setenv("PUBLIC_URL", "https://cvw.example.com/")
    monkeypatch.setattr(password_reset, "smtp_config", lambda: {"host": "smtp"})
    monkeypatch.setattr(auth_routes, "send_password_changed_notice", lambda e: None)
    sent = []
    monkeypatch.setattr(
        auth_routes,
        "send_reset_email",
        lambda email, token: sent.append((email, token)),
    )
    reset_ip_rate_limiter.reset("testclient")
    yield sent
    reset_ip_rate_limiter.reset("testclient")


def _register_and_login(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": PASSWORD},
    )
    return client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    ).json()


def _forgot(client, email):
    return client.post("/auth/forgot-password", json={"email": email})


def _reset(client, token, password=NEW_PASSWORD):
    return client.post(
        "/auth/reset-password", json={"token": token, "new_password": password}
    )


def test_status_says_whether_reset_is_available(client, reset_on, monkeypatch):
    assert client.get("/auth/registration-status").json()["password_reset"] is True
    monkeypatch.delenv("PUBLIC_URL")
    get_settings.cache_clear()
    assert client.get("/auth/registration-status").json()["password_reset"] is False


def test_forgot_password_is_unavailable_without_public_url(client, monkeypatch):
    monkeypatch.setattr(password_reset, "smtp_config", lambda: {"host": "smtp"})
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    assert _forgot(client, "anyone@example.com").status_code == 503


def test_an_unknown_email_gets_the_same_answer_and_no_email(client, reset_on):
    _register_and_login(client, "rsknown")
    known = _forgot(client, "rsknown@example.com")
    unknown = _forgot(client, "nobody-here@example.com")
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()
    assert [email for email, _ in reset_on] == ["rsknown@example.com"]


def test_a_reset_link_sets_the_password_and_signs_out_everywhere(client, reset_on):
    session = _register_and_login(client, "rsflow")
    assert _forgot(client, "RSFlow@example.com").status_code == 200
    [(email, token)] = reset_on
    assert email == "rsflow@example.com"

    assert _reset(client, token).status_code == 200
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    assert client.get("/user", headers=headers).status_code == 401
    login = client.post(
        "/auth/login", json={"email": "rsflow@example.com", "password": NEW_PASSWORD}
    )
    assert login.status_code == 200
    # Single use.
    assert _reset(client, token, "Another789X").status_code == 400


def test_a_new_request_voids_the_older_link(client, reset_on):
    _register_and_login(client, "rstwice")
    _forgot(client, "rstwice@example.com")
    _forgot(client, "rstwice@example.com")
    (_, first), (_, second) = reset_on
    assert _reset(client, first).status_code == 400
    assert _reset(client, second).status_code == 200


def test_an_expired_link_is_rejected(client, reset_on):
    _register_and_login(client, "rsexpired")
    _forgot(client, "rsexpired@example.com")
    [(_, token)] = reset_on
    with SessionLocal() as db:
        row = db.get(PasswordResetToken, hashlib.sha256(token.encode()).hexdigest())
        assert row is not None
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)  # type: ignore[assignment]
        db.commit()
    assert _reset(client, token).status_code == 400


def test_only_a_hash_of_the_token_is_stored(client, reset_on):
    _register_and_login(client, "rshash")
    _forgot(client, "rshash@example.com")
    [(_, token)] = reset_on
    with SessionLocal() as db:
        hashes = {row.token_hash for row in db.query(PasswordResetToken)}
    assert token not in hashes
    assert hashlib.sha256(token.encode()).hexdigest() in hashes


def test_a_weak_password_does_not_spend_the_link(client, reset_on):
    _register_and_login(client, "rsweak")
    _forgot(client, "rsweak@example.com")
    [(_, token)] = reset_on
    assert _reset(client, token, "weak").status_code == 422
    assert _reset(client, token).status_code == 200


def test_reset_requests_for_one_address_are_rate_limited(client, reset_on):
    for _ in range(3):
        assert _forgot(client, "rsflood@example.com").status_code == 200
    response = _forgot(client, "rsflood@example.com")
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_the_emailed_link_uses_public_url_and_a_fragment(monkeypatch):
    monkeypatch.setenv("PUBLIC_URL", "https://cvw.example.com/")
    sent = []
    monkeypatch.setattr(
        password_reset, "send_email", lambda to, subject, body: sent.append(body)
    )
    password_reset.send_reset_email("a@example.com", "tok123")
    assert "https://cvw.example.com/dashboard#reset=tok123" in sent[0]
