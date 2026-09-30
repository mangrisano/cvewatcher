from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.database.models import Asset
from app.services.cve_monitoring import CVEMonitoringService
from app.services.cve_service import CVEService, cve_service
from app.services.findings_repository import FindingRepository
from app.services.token_blocklist import is_token_revoked
from app.utils import rate_limit
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


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """The current user, if listed in ADMIN_EMAILS; 403 otherwise."""
    if (current_user.get("sub") or "").lower() not in get_settings().admin_email_set:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


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


def get_monitoring_service(db: Session = Depends(get_db)) -> CVEMonitoringService:
    return CVEMonitoringService(db)


def get_findings_repository(db: Session = Depends(get_db)) -> FindingRepository:
    return FindingRepository(db)


def get_cve_service() -> CVEService:
    return cve_service


def count_live_lookup(user_email: str) -> None:
    """Count a request that queries NVD / OSV.dev live; 429 once over the quota."""
    limiter = rate_limit.live_lookup_rate_limiter
    retry_after = limiter.retry_after(user_email)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Too many scans or searches, try again later",
            headers={"Retry-After": str(retry_after)},
        )
    limiter.record_failure(user_email)
