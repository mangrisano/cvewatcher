"""Tests for the token blocklist backends and the logout/revocation flow."""

from datetime import datetime, timedelta, timezone

from app.services import token_blocklist
from app.services.token_blocklist import (
    is_token_revoked,
    purge_expired_tokens,
    revoke_token,
)


class FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def set(self, key, value, ex=None):
        self.store[key] = value

    def exists(self, key):
        return 1 if key in self.store else 0


def _make_session():
    from app.database.connection import SessionLocal

    return SessionLocal()


def test_db_backend_revoke_and_check():
    db = _make_session()
    try:
        future = datetime.now(timezone.utc) + timedelta(minutes=30)
        assert is_token_revoked(db, "jti-db-1") is False
        revoke_token(db, "jti-db-1", future)
        assert is_token_revoked(db, "jti-db-1") is True
    finally:
        db.close()


def test_db_backend_ignores_empty_jti():
    db = _make_session()
    try:
        revoke_token(db, None, datetime.now(timezone.utc))
        assert is_token_revoked(db, None) is False
    finally:
        db.close()


def test_purge_expired_tokens():
    db = _make_session()
    try:
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        revoke_token(db, "jti-expired", past)
        removed = purge_expired_tokens(db)
        assert removed >= 1
        assert is_token_revoked(db, "jti-expired") is False
    finally:
        db.close()


def test_redis_backend_used_when_available(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(token_blocklist, "_get_redis", lambda: fake)

    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert is_token_revoked(None, "jti-redis") is False
    revoke_token(None, "jti-redis", expires)
    assert is_token_revoked(None, "jti-redis") is True
    assert "blocklist:jti-redis" in fake.store


def test_logout_revokes_access_token(client):
    client.post(
        "/auth/register",
        json={
            "username": "erin",
            "email": "erin@example.com",
            "password": "Password123",
        },
    )
    token = client.post(
        "/auth/login",
        json={"email": "erin@example.com", "password": "Password123"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/user", headers=headers).status_code == 200

    assert client.post("/auth/logout", headers=headers).status_code == 200

    # The same token must now be rejected.
    assert client.get("/user", headers=headers).status_code == 401


def test_logout_revokes_refresh_token(client):
    client.post(
        "/auth/register",
        json={
            "username": "frank",
            "email": "frank@example.com",
            "password": "Password123",
        },
    )
    login = client.post(
        "/auth/login",
        json={"email": "frank@example.com", "password": "Password123"},
    ).json()
    access = login["access_token"]
    refresh = login["refresh_token"]
    headers = {"Authorization": f"Bearer {access}"}

    assert (
        client.post(
            "/auth/logout", headers=headers, json={"refresh_token": refresh}
        ).status_code
        == 200
    )

    # The revoked refresh token can no longer mint new access tokens.
    response = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 401
