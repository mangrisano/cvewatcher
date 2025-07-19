import datetime
import hashlib
import secrets
import hmac

from fastapi import HTTPException
from jose import jwt
from jose.exceptions import JWTError

ALGORITHM = "HS256"
SECRET_KEY = "your_secret_key"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 with salt (native Python)."""
    salt = secrets.token_bytes(32)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + hashed_password.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt_hex, password_hashed_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_password_hashed = bytes.fromhex(password_hashed_hex)
        password_hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return hmac.compare_digest(password_hashed, stored_password_hashed)
    except (ValueError, TypeError):
        return False


def create_access_token(data: dict) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    to_encode.update(
        {
            "exp": datetime.datetime.now()
            + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> dict:
    """Verify a JWT access token and return its payload."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception:
        raise HTTPException(status_code=401, detail="Error decoding token.")
