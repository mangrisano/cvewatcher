"""Unit tests for JWT/password helpers backed by joserfc."""

import datetime
import hashlib
import secrets

import pytest
from fastapi import HTTPException

from app.database.connection import SessionLocal
from app.database.models import User
from app.routes import auth as auth_routes
from app.utils import auth


def _legacy_hash(password: str) -> str:
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}:{digest.hex()}"


def test_password_hash_roundtrip():
    hashed = auth.hash_password("Sup3rSecret!")
    assert hashed.startswith(f"pbkdf2_sha256${auth.PASSWORD_HASH_ITERATIONS}$")
    assert auth.PASSWORD_HASH_ITERATIONS >= 600_000
    assert auth.verify_password("Sup3rSecret!", hashed)
    assert not auth.verify_password("wrong", hashed)
    assert not auth.password_needs_rehash(hashed)


def test_legacy_password_hashes_still_verify_and_need_rehash():
    legacy = _legacy_hash("Sup3rSecret!")
    assert auth.verify_password("Sup3rSecret!", legacy)
    assert not auth.verify_password("wrong", legacy)
    assert auth.password_needs_rehash(legacy)
    assert not auth.verify_password("x", "garbage")


def test_login_upgrades_a_legacy_password_hash(client):
    db = SessionLocal()
    try:
        db.add(
            User(
                username="legacyhash",
                email="legacyhash@example.com",
                password_hash=_legacy_hash("Password123"),
            )
        )
        db.commit()
        response = client.post(
            "/auth/login",
            json={"email": "legacyhash@example.com", "password": "Password123"},
        )
        assert response.status_code == 200
        db.expire_all()
        stored = db.query(User).filter(User.username == "legacyhash").one()
        assert stored.password_hash.startswith("pbkdf2_sha256$")
        assert auth.verify_password("Password123", str(stored.password_hash))
    finally:
        db.query(User).filter(User.username == "legacyhash").delete()
        db.commit()
        db.close()


def test_login_with_unknown_email_still_hashes_the_password(client, monkeypatch):
    calls = []
    monkeypatch.setattr(auth_routes, "spend_password_check", calls.append)
    response = client.post(
        "/auth/login", json={"email": "nobody-here@example.com", "password": "abc"}
    )
    assert response.status_code == 401
    assert calls == ["abc"]


def test_access_token_roundtrip():
    token = auth.create_access_token({"sub": "user@example.com"})
    claims = auth.verify_access_token(token)
    assert claims["sub"] == "user@example.com"


def test_expired_token_is_rejected():
    token = auth.create_access_token(
        {"sub": "user@example.com"},
        expires_delta=datetime.timedelta(seconds=-1),
    )
    with pytest.raises(HTTPException) as exc:
        auth.verify_access_token(token)
    assert exc.value.status_code == 401


def test_tampered_token_is_rejected():
    token = auth.create_access_token({"sub": "user@example.com"})
    with pytest.raises(HTTPException) as exc:
        auth.verify_access_token(token + "tampered")
    assert exc.value.status_code == 401


def test_refresh_token_rejects_access_token():
    access = auth.create_access_token({"sub": "user@example.com"})
    with pytest.raises(HTTPException) as exc:
        auth.verify_refresh_token(access)
    assert exc.value.status_code == 401


def test_refresh_token_roundtrip():
    token = auth.create_refresh_token({"sub": "user@example.com"})
    claims = auth.verify_refresh_token(token)
    assert claims["type"] == "refresh"


def test_access_token_rejects_refresh_token():
    refresh = auth.create_refresh_token({"sub": "user@example.com"})
    with pytest.raises(HTTPException) as exc:
        auth.verify_access_token(refresh)
    assert exc.value.status_code == 401


def test_refresh_token_cannot_call_the_api(client):
    refresh = auth.create_refresh_token({"sub": "user@example.com"})
    response = client.get("/assets/", headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 401


def test_login_treats_a_policy_breaking_password_as_wrong(client):
    client.post(
        "/auth/register",
        json={
            "username": "shortpw",
            "email": "shortpw@example.com",
            "password": "Password123",
        },
    )
    response = client.post(
        "/auth/login", json={"email": "shortpw@example.com", "password": "abcd"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_short_jwt_secret_is_rejected_at_startup():
    import os
    import subprocess
    import sys

    env = {**os.environ, "JWT_SECRET_KEY": "too-short"}
    result = subprocess.run(
        [sys.executable, "-c", "import app.utils.auth"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "at least 32 bytes" in result.stderr
