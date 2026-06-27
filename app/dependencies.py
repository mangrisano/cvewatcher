from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.utils.auth import verify_access_token


def get_current_user(
    authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
) -> dict:
    token = authorization.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    payload = verify_access_token(token)
    return payload
