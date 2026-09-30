"""Changing the password from the app, and signing out the other sessions."""

from app.database.connection import SessionLocal
from app.database.models import User
from app.routes import user as user_routes
from app.utils import auth

PASSWORD = "Password123"
NEW_PASSWORD = "NewPassword456"


def _register_and_login(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": PASSWORD},
    )
    return client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    ).json()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _change(client, token, current=PASSWORD, new=NEW_PASSWORD):
    return client.post(
        "/user/password",
        json={"current_password": current, "new_password": new},
        headers=_bearer(token),
    )


def test_changing_the_password_signs_out_the_other_sessions(client):
    other = _register_and_login(client, "pwone")
    this = client.post(
        "/auth/login", json={"email": "pwone@example.com", "password": PASSWORD}
    ).json()

    response = _change(client, this["access_token"])
    assert response.status_code == 200
    fresh = response.json()

    # Every session issued before the change is gone, this one's old pair too.
    for old in (other, this):
        assert (
            client.get("/user", headers=_bearer(old["access_token"])).status_code == 401
        )
        refreshed = client.post(
            "/auth/refresh", json={"refresh_token": old["refresh_token"]}
        )
        assert refreshed.status_code == 401

    # The pair returned by the change keeps the current session signed in.
    assert (
        client.get("/user", headers=_bearer(fresh["access_token"])).status_code == 200
    )
    rotated = client.post(
        "/auth/refresh", json={"refresh_token": fresh["refresh_token"]}
    )
    assert rotated.status_code == 200

    login = client.post(
        "/auth/login", json={"email": "pwone@example.com", "password": PASSWORD}
    )
    assert login.status_code == 401
    login = client.post(
        "/auth/login", json={"email": "pwone@example.com", "password": NEW_PASSWORD}
    )
    assert login.status_code == 200


def test_a_wrong_current_password_is_rejected_without_signing_out(client):
    session = _register_and_login(client, "pwtwo")
    response = _change(client, session["access_token"], current="Wrong12345")
    # 400, not 401: the client must not treat it as an expired session.
    assert response.status_code == 400
    assert (
        client.get("/user", headers=_bearer(session["access_token"])).status_code == 200
    )


def test_guessing_the_current_password_is_rate_limited(client):
    session = _register_and_login(client, "pwthree")
    for _ in range(5):
        assert (
            _change(client, session["access_token"], current="Wrong12345").status_code
            == 400
        )
    response = _change(client, session["access_token"])
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    user_routes._password_rate_limiter.reset("pwthree@example.com")


def test_the_new_password_must_follow_the_rules_and_differ(client):
    session = _register_and_login(client, "pwfour")
    assert _change(client, session["access_token"], new="short").status_code == 422
    same = _change(client, session["access_token"], new=PASSWORD)
    assert same.status_code == 400


def test_the_owner_is_told_by_email_when_smtp_is_configured(client, monkeypatch):
    sent = []
    monkeypatch.setattr(user_routes, "smtp_config", lambda: {"host": "smtp"})
    monkeypatch.setattr(
        user_routes, "send_email", lambda to, subject, body: sent.append((to, subject))
    )
    session = _register_and_login(client, "pwfive")
    assert _change(client, session["access_token"]).status_code == 200
    assert sent == [(["pwfive@example.com"], "[CVE Watcher] Your password was changed")]


def test_tokens_without_a_session_version_still_work_until_a_change(client):
    # Sessions opened before this release carry no "ver" claim.
    _register_and_login(client, "pwsix")
    legacy = auth.create_access_token({"sub": "pwsix@example.com"})
    assert client.get("/user", headers=_bearer(legacy)).status_code == 200


def test_tokens_of_a_deleted_account_are_rejected(client):
    session = _register_and_login(client, "pwseven")
    with SessionLocal() as db:
        db.query(User).filter(User.email == "pwseven@example.com").delete()
        db.commit()
    assert (
        client.get("/user", headers=_bearer(session["access_token"])).status_code == 401
    )
