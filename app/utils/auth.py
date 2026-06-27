import datetime
import hashlib
import secrets
import hmac
import os
from typing import Optional

from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import JoseError

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_secret_key = os.getenv("JWT_SECRET_KEY")

if not _secret_key:
    raise ValueError("JWT_SECRET_KEY environment variable is required")

SECRET_KEY: str = _secret_key
_JWT_KEY = OctKey.import_key(SECRET_KEY)
_CLAIMS_REGISTRY = jwt.JWTClaimsRegistry()

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(32)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + hashed_password.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, password_hashed_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_password_hashed = bytes.fromhex(password_hashed_hex)
        password_hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return hmac.compare_digest(password_hashed, stored_password_hashed)
    except (ValueError, TypeError):
        return False


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
            "type": "refresh",
        }
    )
    return jwt.encode({"alg": ALGORITHM}, to_encode, _JWT_KEY)


def verify_access_token(token: str) -> dict:
    try:
        decoded = jwt.decode(token, _JWT_KEY, algorithms=[ALGORITHM])
        _CLAIMS_REGISTRY.validate(decoded.claims)
        return decoded.claims
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
