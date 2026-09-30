"""Sign-up confirmation: new accounts stay inactive until their emailed link is opened."""

import pytest

from app.config import get_settings
from app.database.connection import SessionLocal
from app.database.models import User
from app.routes import auth as auth_routes
from app.services import account_emails
from app.utils.rate_limit import reset_ip_rate_limiter

PASSWORD = "Password123"


@pytest.fixture
def email_on(monkeypatch):
    """Email enabled; returns the (email, token) pairs that would be emailed."""
    monkeypatch.setenv("PUBLIC_URL", "https://cvw.example.com")
    monkeypatch.setattr(account_emails, "smtp_config", lambda: {"host": "smtp"})
    monkeypatch.setattr(auth_routes, "send_password_changed_notice", lambda e: None)
    monkeypatch.setattr(auth_routes, "send_reset_email", lambda e, t: None)
    sent = []
    monkeypatch.setattr(
        auth_routes,
        "send_verification_email",
        lambda email, token: sent.append((email, token)),
    )
    reset_ip_rate_limiter.reset("testclient")
    yield sent
    reset_ip_rate_limiter.reset("testclient")


def _register(client, username, password=PASSWORD):
    return client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )


def _login(client, username, password=PASSWORD):
    return client.post(
        "/auth/login",
        json={"email": f"{username}@example.com", "password": password},
    )


def _verify(client, token):
    return client.post("/auth/verify-email", json={"token": token})


def test_without_email_new_accounts_are_active_at_once(client):
    response = _register(client, "vfnomail")
    assert response.json()["verification_required"] is False
    assert _login(client, "vfnomail").status_code == 200


def test_a_new_account_signs_in_only_after_confirming(client, email_on):
    response = _register(client, "vfflow")
    assert response.json()["verification_required"] is True
    [(email, token)] = email_on
    assert email == "vfflow@example.com"

    assert _login(client, "vfflow").status_code == 403
    assert _verify(client, token).status_code == 200
    assert _login(client, "vfflow").status_code == 200
    # Single use.
    assert _verify(client, token).status_code == 400


def test_a_wrong_password_never_reveals_a_pending_account(client, email_on):
    _register(client, "vfwrong")
    assert _login(client, "vfwrong", password="Wrong12345").status_code == 401


def test_resending_replaces_the_link_and_stays_generic(client, email_on):
    _register(client, "vfresend")
    resent = client.post(
        "/auth/resend-verification", json={"email": "vfresend@example.com"}
    )
    unknown = client.post(
        "/auth/resend-verification", json={"email": "nobody-vf@example.com"}
    )
    assert resent.status_code == unknown.status_code == 200
    assert resent.json() == unknown.json()
    (_, first), (_, second) = email_on
    assert _verify(client, first).status_code == 400
    assert _verify(client, second).status_code == 200


def test_confirmed_accounts_get_no_new_link(client, email_on):
    _register(client, "vfdone")
    [(_, token)] = email_on
    _verify(client, token)
    client.post("/auth/resend-verification", json={"email": "vfdone@example.com"})
    assert len(email_on) == 1


def test_a_password_reset_also_confirms_the_address(client, email_on, monkeypatch):
    reset_tokens = []
    monkeypatch.setattr(
        auth_routes, "send_reset_email", lambda e, t: reset_tokens.append(t)
    )
    _register(client, "vfreset")
    client.post("/auth/forgot-password", json={"email": "vfreset@example.com"})
    client.post(
        "/auth/reset-password",
        json={"token": reset_tokens[0], "new_password": "NewPassword456"},
    )
    assert _login(client, "vfreset", password="NewPassword456").status_code == 200


def test_pending_accounts_can_sign_in_once_email_is_turned_off(
    client, email_on, monkeypatch
):
    _register(client, "vfoff")
    assert _login(client, "vfoff").status_code == 403
    # Nothing could deliver the link any more, so the check steps aside.
    monkeypatch.delenv("PUBLIC_URL")
    get_settings.cache_clear()
    assert _login(client, "vfoff").status_code == 200


def test_existing_accounts_count_as_confirmed(client):
    _register(client, "vfold")
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == "vfold@example.com").one()
        assert user.email_verified is True
