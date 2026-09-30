"""Best-effort in-memory rate limiter for login attempts.

Note: state lives in the process memory, so it is per-worker and resets on
restart. For multi-process / multi-instance deployments a shared store
(e.g. Redis) would be required. It is meant to slow down brute-force attempts,
not to be an authoritative quota.
"""

import threading
import time
from collections import defaultdict, deque

from app.config import get_settings


class InMemoryRateLimiter:
    # Every N recorded failures, drop keys whose attempts all left the window.
    SWEEP_EVERY = 1000

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._since_sweep = 0

    def _prune(self, key: str, now: float) -> None:
        attempts = self._attempts.get(key)
        if attempts is None:
            return
        cutoff = now - self.window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if not attempts:
            del self._attempts[key]

    def _sweep(self, now: float) -> None:
        for key in list(self._attempts):
            self._prune(key, now)

    def retry_after(self, key: str) -> int:
        """Return seconds to wait if the key is blocked, otherwise 0."""
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            attempts = self._attempts.get(key)
            if attempts and len(attempts) >= self.max_attempts:
                return int(self.window_seconds - (now - attempts[0])) + 1
            return 0

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._since_sweep += 1
            if self._since_sweep >= self.SWEEP_EVERY:
                self._since_sweep = 0
                self._sweep(now)
            self._prune(key, now)
            self._attempts[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


_settings = get_settings()

login_rate_limiter = InMemoryRateLimiter(
    max_attempts=_settings.login_max_attempts,
    window_seconds=_settings.login_window_seconds,
)

# Per source IP across all accounts, against password spraying.
login_ip_rate_limiter = InMemoryRateLimiter(
    max_attempts=_settings.login_ip_max_attempts,
    window_seconds=_settings.login_window_seconds,
)

registration_rate_limiter = InMemoryRateLimiter(
    max_attempts=_settings.register_max_attempts,
    window_seconds=_settings.register_window_seconds,
)

# Requests that query NVD / OSV.dev live, so no user can exhaust NVD's limit.
live_lookup_rate_limiter = InMemoryRateLimiter(
    max_attempts=_settings.live_lookups_per_hour, window_seconds=3600
)

# Reset emails: per address so nobody is flooded, per IP against enumeration.
reset_email_rate_limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=3600)
reset_ip_rate_limiter = InMemoryRateLimiter(max_attempts=10, window_seconds=3600)
