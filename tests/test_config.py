"""Tests for the typed application settings."""

import pytest
from pydantic import ValidationError

from app.config import Settings

_SECRET = "x" * 32


def test_defaults(monkeypatch):
    for name in (
        "MONITOR_ENABLED",
        "ENRICH_ENABLED",
        "NVD_MAX_CONCURRENCY",
        "NOTIFY_EMAIL_TO",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(jwt_secret_key=_SECRET)
    assert settings.monitor_enabled is False
    assert settings.enrich_enabled is True
    assert settings.nvd_max_concurrency is None
    assert settings.notify_email_recipients == []


@pytest.mark.parametrize("raw", ["1", "true", "YES", "on"])
def test_booleans_accept_the_usual_spellings(monkeypatch, raw):
    monkeypatch.setenv("MONITOR_ENABLED", raw)
    assert Settings(jwt_secret_key=_SECRET).monitor_enabled is True


def test_empty_variables_keep_the_default(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "")
    monkeypatch.setenv("ENRICH_ENABLED", "")
    settings = Settings(jwt_secret_key=_SECRET)
    assert settings.nvd_api_key is None
    assert settings.enrich_enabled is True


@pytest.mark.parametrize(
    "name,value",
    [
        ("MONITOR_ENABLED", "maybe"),
        ("NVD_MAX_CONCURRENCY", "0"),
        ("MONITOR_INTERVAL_MINUTES", "often"),
        ("JWT_SECRET_KEY", "short"),
    ],
)
def test_invalid_values_are_rejected(monkeypatch, name, value):
    monkeypatch.setenv("JWT_SECRET_KEY", _SECRET)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_email_recipients_are_split_and_trimmed(monkeypatch):
    monkeypatch.setenv("NOTIFY_EMAIL_TO", " ops@example.com, ,sec@example.com ")
    assert Settings(jwt_secret_key=_SECRET).notify_email_recipients == [
        "ops@example.com",
        "sec@example.com",
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("postgresql+psycopg2://u:p@db/cvw", "postgresql+psycopg://u:p@db/cvw"),
        ("postgresql://u:p@db/cvw", "postgresql://u:p@db/cvw"),
        ("sqlite:///./cvewatcher.db", "sqlite:///./cvewatcher.db"),
    ],
)
def test_psycopg2_urls_move_to_psycopg3(raw, expected):
    # Only psycopg 3 is installed, so an old explicit psycopg2 URL must still work.
    assert Settings(jwt_secret_key=_SECRET, database_url=raw).database_url == expected
