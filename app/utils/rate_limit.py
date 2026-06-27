"""Best-effort in-memory rate limiter for login attempts.

Note: state lives in the process memory, so it is per-worker and resets on
restart. For multi-process / multi-instance deployments a shared store
(e.g. Redis) would be required. It is meant to slow down brute-force attempts,
not to be an authoritative quota.
"""

import os
import threading
import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> None:
        attempts = self._attempts[key]
        cutoff = now - self.window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

    def retry_after(self, key: str) -> int:
        """Return seconds to wait if the key is blocked, otherwise 0."""
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            attempts = self._attempts[key]
            if len(attempts) >= self.max_attempts:
                return int(self.window_seconds - (now - attempts[0])) + 1
            return 0

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            self._attempts[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


login_rate_limiter = InMemoryRateLimiter(
    max_attempts=int(os.getenv("LOGIN_MAX_ATTEMPTS", "5")),
    window_seconds=int(os.getenv("LOGIN_WINDOW_SECONDS", "300")),
)
