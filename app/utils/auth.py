import datetime
import hashlib
import secrets
import hmac
import uuid
from typing import Optional

from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import JoseError

from app.config import get_settings

_settings = get_settings()
ALGORITHM = _settings.jwt_algorithm

if not _settings.jwt_secret_key:
    raise ValueError("JWT_SECRET_KEY environment variable is required")

SECRET_KEY: str = _settings.jwt_secret_key
_JWT_KEY = OctKey.import_key(SECRET_KEY)
_CLAIMS_REGISTRY = jwt.JWTClaimsRegistry()

ACCESS_TOKEN_EXPIRE_MINUTES = _settings.jwt_access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = _settings.jwt_refresh_token_expire_days

# OWASP's current minimum for PBKDF2-HMAC-SHA256.
PASSWORD_HASH_ITERATIONS = 600_000
_HASH_SCHEME = "pbkdf2_sha256"
# Hashes written before 2.7.2 are "salt:digest" at this fixed count.
_LEGACY_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(32)
    iterations = PASSWORD_HASH_ITERATIONS
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_HASH_SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def _parse_hash(stored_hash: str) -> tuple[int, bytes, bytes]:
    if stored_hash.startswith(f"{_HASH_SCHEME}$"):
        _, iterations, salt_hex, digest_hex = stored_hash.split("$")
        return int(iterations), bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
    salt_hex, digest_hex = stored_hash.split(":")
    return _LEGACY_ITERATIONS, bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        iterations, salt, expected = _parse_hash(stored_hash)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(digest, expected)


def password_needs_rehash(stored_hash: str) -> bool:
    """True when the hash uses fewer iterations than the current setting."""
    try:
        iterations, _, _ = _parse_hash(stored_hash)
    except (ValueError, TypeError):
        return True
    return iterations < PASSWORD_HASH_ITERATIONS


def spend_password_check(password: str) -> None:
    """Take as long as a real check, so unknown emails can't be told by timing."""
    hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes(32), PASSWORD_HASH_ITERATIONS
    )


def create_access_token(
    data: dict, expires_delta: Optional[datetime.timedelta] = None
) -> str:
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update(
        {
            "exp": int(expire.timestamp()),
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "jti": uuid.uuid4().hex,
            "type": "access",
        }
    )
    return jwt.encode({"alg": ALGORITHM}, to_encode, _JWT_KEY)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode.update(
        {
            "exp": int(expire.timestamp()),
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "jti": uuid.uuid4().hex,
            "type": "refresh",
        }
    )
    return jwt.encode({"alg": ALGORITHM}, to_encode, _JWT_KEY)


def verify_access_token(token: str) -> dict:
    try:
        decoded = jwt.decode(token, _JWT_KEY, algorithms=[ALGORITHM])
        _CLAIMS_REGISTRY.validate(decoded.claims)
        claims = decoded.claims

        # Tokens issued before the "type" claim existed are access tokens.
        if claims.get("type", "access") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        return claims
    except HTTPException:
        raise
    except JoseError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception:
        raise HTTPException(status_code=401, detail="Error decoding token")


def verify_refresh_token(token: str) -> dict:
    try:
        decoded = jwt.decode(token, _JWT_KEY, algorithms=[ALGORITHM])
        _CLAIMS_REGISTRY.validate(decoded.claims)
        claims = decoded.claims

        if claims.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        return claims
    except HTTPException:
        raise
    except JoseError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    except Exception:
        raise HTTPException(status_code=401, detail="Error decoding refresh token")
