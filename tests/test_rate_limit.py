"""Tests for login rate limiting and password policy."""

import pytest

from app.models import validate_password_strength
from app.utils import rate_limit
from app.utils.rate_limit import InMemoryRateLimiter, login_rate_limiter


def test_password_policy_accepts_strong_password():
    assert validate_password_strength("Password123") == "Password123"


@pytest.mark.parametrize(
    "password",
    [
        "short",  # too short
        "alllowercase1",  # no uppercase
        "ALLUPPERCASE1",  # no lowercase
        "NoDigitsHere",  # no digit
    ],
)
def test_password_policy_rejects_weak_passwords(password):
    with pytest.raises(ValueError):
        validate_password_strength(password)


def test_rate_limiter_blocks_after_max_attempts(monkeypatch):
    fake_time = {"now": 1000.0}
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: fake_time["now"])

    limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=60)
    key = "user@example.com:1.2.3.4"

    for _ in range(3):
        assert limiter.retry_after(key) == 0
        limiter.record_failure(key)

    assert limiter.retry_after(key) > 0


def test_rate_limiter_window_expires(monkeypatch):
    fake_time = {"now": 1000.0}
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: fake_time["now"])

    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=60)
    key = "user@example.com:1.2.3.4"

    limiter.record_failure(key)
    limiter.record_failure(key)
    assert limiter.retry_after(key) > 0

    # Advance past the window: old attempts are pruned.
    fake_time["now"] += 61
    assert limiter.retry_after(key) == 0


def test_rate_limiter_reset_clears_attempts():
    limiter = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    key = "user@example.com:1.2.3.4"
    limiter.record_failure(key)
    assert limiter.retry_after(key) > 0
    limiter.reset(key)
    assert limiter.retry_after(key) == 0


def test_login_is_rate_limited_after_repeated_failures(client):
    email = "ratelimited@example.com"
    client.post(
        "/auth/register",
        json={"username": "ratelimited", "email": email, "password": "Password123"},
    )

    # Exhaust the allowed attempts with wrong passwords.
    last_status = None
    for _ in range(login_rate_limiter.max_attempts + 1):
        last_status = client.post(
            "/auth/login",
            json={"email": email, "password": "WrongPass123"},
        ).status_code

    assert last_status == 429

    # Cleanup shared limiter state for other tests.
    login_rate_limiter.reset(f"{email}:testclient")
