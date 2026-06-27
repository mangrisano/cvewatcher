"""Unit tests for JWT/password helpers backed by joserfc."""

import datetime

import pytest
from fastapi import HTTPException

from app.utils import auth


def test_password_hash_roundtrip():
    hashed = auth.hash_password("Sup3rSecret!")
    assert auth.verify_password("Sup3rSecret!", hashed)
    assert not auth.verify_password("wrong", hashed)


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
