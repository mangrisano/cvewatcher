"""Token revocation list (denylist) with a pluggable backend.

Logout adds a token's ``jti`` here so it can no longer be used, even though
JWTs are otherwise stateless.

Backends:
- **Redis** when ``REDIS_URL`` is set: keys carry a TTL equal to the token
  lifetime, so expired entries clean themselves up and state is shared across
  workers/instances. If Redis is unreachable the check fails closed
  (:class:`BlocklistUnavailableError`, served as 503) instead of silently
  falling back to a per-process view that would accept revoked tokens.
- **Database** otherwise: rows store the token expiry; expired rows are pruned
  on every revocation (or explicitly with :func:`purge_expired_tokens`).
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.models import RevokedToken

logger = logging.getLogger(__name__)

_redis_client: Optional[Any] = None


class BlocklistUnavailableError(Exception):
    """The configured revocation backend cannot be reached."""


def _get_redis() -> Optional[Any]:
    global _redis_client
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return None
    if _redis_client is None:
        import redis

        # Connects lazily and reconnects on its own after an outage.
        _redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        logger.info("Token blocklist using Redis backend")
    return _redis_client


def _redis_call(operation, *args, **kwargs):
    import redis

    try:
        return operation(*args, **kwargs)
    except redis.RedisError as e:
        logger.error("Redis blocklist unavailable: %s", e)
        raise BlocklistUnavailableError("Token revocation backend unavailable") from e


def _redis_key(jti: str) -> str:
    return f"blocklist:{jti}"


def revoke_token(db: Session, jti: Optional[str], expires_at: datetime) -> None:
    if not jti:
        return

    client = _get_redis()
    if client is not None:
        ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
        _redis_call(client.set, _redis_key(jti), "1", ex=max(ttl, 1))
        return

    now = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(
        synchronize_session=False
    )
    if not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
    try:
        db.commit()
    except IntegrityError:
        # A concurrent request revoked the same token first.
        db.rollback()


def is_token_revoked(db: Session, jti: Optional[str]) -> bool:
    if not jti:
        return False

    client = _get_redis()
    if client is not None:
        return bool(_redis_call(client.exists, _redis_key(jti)))

    return db.query(RevokedToken).filter(RevokedToken.jti == jti).first() is not None


def purge_expired_tokens(db: Session) -> int:
    """Remove expired entries from the database backend.

    No-op for Redis, which expires keys automatically via TTL.
    """
    if _get_redis() is not None:
        return 0

    now = datetime.now(timezone.utc)
    deleted = db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete()
    db.commit()
    return deleted
