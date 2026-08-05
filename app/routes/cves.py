import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.dependencies import get_current_user
from app.models import VulnerabilityResponse
from app.services.cve_service import cve_service
from app.services.cve_monitoring import CVEMonitoringService
from app.services.nist_nvd import NvdUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cves", tags=["CVE"])


def _public_affected_products(products) -> list[dict]:
    """Drop any legacy per-asset tracking entries (which carried tenant data).

    Defence in depth: the tenant tracking now lives in ``asset_cves``, but a
    deployment that has not yet run the scrub migration could still have such
    dicts in ``cves.affected_products``; never expose them.
    """
    if not isinstance(products, list):
        return []
    return [
        product
        for product in products
        if not (isinstance(product, dict) and "user_email" in product)
    ]


class CVEResponse(BaseModel):
    cve_id: str
    summary: Optional[str]
    severity: Optional[str]
    score: Optional[float]
    publish_date: Optional[str]
    modified_date: Optional[str]
    affected_products: Optional[list[dict]]

    model_config = ConfigDict(from_attributes=True)


@router.get("/fetch-recent")
async def fetch_recent_cves(
    days: int = Query(default=7, ge=1, le=30, description="Days back to search"),
    current_user: dict = Depends(get_current_user),
):
    try:
        stored_count = cve_service.fetch_and_store_recent_cves(days=days)
        return {
            "message": f"Retrieved and saved {stored_count} CVEs from the last {days} days",
            "stored_count": stored_count,
            "days": days,
        }
    except Exception:
        logger.exception("Error retrieving recent CVEs")
        raise HTTPException(status_code=500, detail="Error retrieving CVEs")


@router.get("/recent", response_model=list[CVEResponse])
async def get_recent_cves(
    limit: int = Query(default=20, ge=1, le=100, description="Number of CVE to return"),
    offset: int = Query(default=0, ge=0, description="Number of CVE to skip"),
    current_user: dict = Depends(get_current_user),
):
    try:
        cves = cve_service.get_stored_cves(limit=limit, offset=offset)

        response = []
        for cve in cves:
            cve_response = CVEResponse(
                cve_id=str(cve.id),
                summary=str(cve.summary) if cve.summary else None,
                severity=str(cve.severity) if cve.severity else None,
                score=float(cve.score) if cve.score else None,  # type: ignore
                publish_date=cve.publish_date.isoformat() if cve.publish_date else None,
                modified_date=cve.modified_date.isoformat()
                if cve.modified_date is not None
                else None,
                affected_products=_public_affected_products(cve.affected_products),
            )
            response.append(cve_response)

        return response
    except Exception:
        logger.exception("Error retrieving stored CVEs")
        raise HTTPException(status_code=500, detail="Error retrieving CVEs")


@router.get("/vulnerabilities", response_model=list[VulnerabilityResponse])
async def check_my_vulnerabilities(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = current_user.get("sub")
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid user token")

    try:
        service = CVEMonitoringService(db)
        vulnerabilities = await service.get_user_vulnerabilities(user_email)

        return [VulnerabilityResponse(**vuln) for vuln in vulnerabilities]
    except NvdUnavailableError as e:
        raise HTTPException(
            status_code=503,
            detail=f"NVD service is currently unavailable. Please retry later. ({e})",
        )
    except Exception:
        logger.exception("Error checking vulnerabilities for %s", user_email)
        raise HTTPException(status_code=500, detail="Error checking vulnerabilities")


@router.get("/search")
async def search_cves(
    product: str = Query(description="Product name to search"),
    version: Optional[str] = Query(
        default=None, description="Product version (optional)"
    ),
    current_user: dict = Depends(get_current_user),
):
    try:
        cves = cve_service.search_cves_for_asset(product, version)

        response = []
        for cve_data in cves:
            cve_response = {
                "cve_id": cve_data.cve_id,
                "summary": cve_data.summary,
                "severity": cve_data.severity,
                "score": cve_data.score,
                "publish_date": cve_data.publish_date.isoformat()
                if cve_data.publish_date
                else None,
                "modified_date": cve_data.modified_date.isoformat()
                if cve_data.modified_date
                else None,
                "affected_products": cve_data.affected_products,
                "references": cve_data.references,
            }
            response.append(cve_response)

        return {
            "product": product,
            "version": version,
            "cve_count": len(cves),
            "cves": response,
        }
    except Exception:
        logger.exception("Error searching CVEs for product %s", product)
        raise HTTPException(status_code=500, detail="Error searching CVEs")
