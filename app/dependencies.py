from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.database.models import Asset
from app.services.token_blocklist import is_token_revoked
from app.utils.auth import verify_access_token


def get_current_user(
    authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: Session = Depends(get_db),
) -> dict:
    token = authorization.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    payload = verify_access_token(token)
    if is_token_revoked(db, payload.get("jti")):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    return payload


def get_owned_asset(
    asset_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Asset:
    """The ``{asset_id}`` asset of the current user; 404 if missing or not theirs."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
