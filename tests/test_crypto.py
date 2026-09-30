"""Tests for encryption at rest of user secrets."""

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.utils import crypto


def test_encrypt_roundtrip_hides_the_plaintext():
    token = crypto.encrypt("https://hooks.slack.com/services/secret")
    assert "secret" not in token
    assert crypto.decrypt(token) == "https://hooks.slack.com/services/secret"


def test_value_from_another_key_reads_as_unset(monkeypatch):
    token = crypto.encrypt("secret")
    monkeypatch.setenv("SECRETS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    crypto.get_settings.cache_clear()
    assert crypto.decrypt(token) is None
    assert crypto.decrypt("not-a-token") is None


def test_dedicated_key_is_used_when_set(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("SECRETS_ENCRYPTION_KEY", key.decode())
    crypto.get_settings.cache_clear()
    assert Fernet(key).decrypt(crypto.encrypt("x").encode()) == b"x"


def test_invalid_encryption_key_is_rejected_at_startup():
    with pytest.raises(ValueError, match="SECRETS_ENCRYPTION_KEY"):
        Settings(secrets_encryption_key="too-short")
