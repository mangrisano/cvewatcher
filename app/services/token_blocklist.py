"""Token revocation list (denylist) with a pluggable backend.

Logout and refresh-token rotation add a token's ``jti`` here so it can no longer
be used, even though JWTs are otherwise stateless.

Backends:
- **Redis** (preferred) when ``REDIS_URL`` is set: keys carry a TTL equal to the
  token lifetime, so expired entries clean themselves up and state is shared
  across workers/instances.
- **Database** fallback otherwise: rows store the token expiry and can be pruned
  with :func:`purge_expired_tokens`.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.database.models import RevokedToken

logger = logging.getLogger(__name__)

_redis_client: Optional[Any] = None
_redis_initialized = False


def _get_redis() -> Optional[Any]:
    global _redis_client, _redis_initialized
    if _redis_initialized:
        return _redis_client

    _redis_initialized = True
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        _redis_client = None
        return None

    try:
        import redis

        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        _redis_client = client
        logger.info("Token blocklist using Redis backend")
    except Exception as e:
        logger.error("Redis unavailable (%s); falling back to database blocklist", e)
        _redis_client = None

    return _redis_client


def _redis_key(jti: str) -> str:
    return f"blocklist:{jti}"


def revoke_token(db: Session, jti: Optional[str], expires_at: datetime) -> None:
    if not jti:
        return

    client = _get_redis()
    if client is not None:
        ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
        client.set(_redis_key(jti), "1", ex=max(ttl, 1))
        return

    if db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        return
    db.add(RevokedToken(jti=jti, expires_at=expires_at))
    db.commit()


def is_token_revoked(db: Session, jti: Optional[str]) -> bool:
    if not jti:
        return False

    client = _get_redis()
    if client is not None:
        return bool(client.exists(_redis_key(jti)))

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
