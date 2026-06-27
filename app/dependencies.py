from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
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
