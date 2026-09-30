"""Encryption at rest for user secrets (chat webhook URLs, bot tokens).

Uses Fernet (AES-128-CBC + HMAC-SHA256). The key is SECRETS_ENCRYPTION_KEY
when set, otherwise one derived from JWT_SECRET_KEY, so changing either key
makes the stored secrets unreadable (they then read as unset).
"""

import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings

logger = logging.getLogger(__name__)


def _fernet() -> Fernet:
    settings = get_settings()
    if settings.secrets_encryption_key:
        return Fernet(settings.secrets_encryption_key)
    if not settings.jwt_secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable is required")
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cvewatcher/secrets/v1",
    ).derive(settings.jwt_secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> Optional[str]:
    """The plaintext, or None when the current key cannot read the value."""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        logger.warning("A stored secret could not be decrypted (was the key changed?)")
        return None
