"""
CVE Routes
Endpoints for CVE management and vulnerability monitoring
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.services.cve_service import cve_service

router = APIRouter(prefix="/cves", tags=["CVE"])


class CVEResponse(BaseModel):
    """Response for a single CVE"""

    cve_id: str
    summary: Optional[str]
    severity: Optional[str]
    score: Optional[float]
    publish_date: Optional[str]
    modified_date: Optional[str]
    affected_products: Optional[List[dict]]

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    """Response for a vulnerability found in user assets"""

    asset_id: int
    asset_name: str
    asset_version: Optional[str]
    cve_id: str
    severity: Optional[str]
    score: Optional[float]
    summary: Optional[str]
    publish_date: Optional[str]


@router.post("/fetch-recent")
async def fetch_recent_cves(
    days: int = Query(default=7, ge=1, le=30, description="Days back to search"),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve and save recent CVEs from NIST NVD
    Requires user authentication
    """
    try:
        stored_count = cve_service.fetch_and_store_recent_cves(days=days)
        return {
            "message": f"Retrieved and saved {stored_count} CVEs from the last {days} days",
            "stored_count": stored_count,
            "days": days,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error in retrieving CVE: {str(e)}"
        )


@router.get("/recent", response_model=List[CVEResponse])
async def get_recent_cves(
    limit: int = Query(default=20, ge=1, le=100, description="Number of CVE to return"),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve recent CVEs saved in the database
    """
    try:
        cves = cve_service.get_stored_cves(limit=limit)

        response = []
        for cve in cves:
            cve_response = CVEResponse(
                cve_id=str(cve.id),  # type: ignore
                summary=str(cve.summary) if cve.summary else None,  # type: ignore
                severity=str(cve.severity) if cve.severity else None,  # type: ignore
                score=float(cve.score) if cve.score else None,  # type: ignore
                publish_date=cve.publish_date.isoformat() if cve.publish_date else None,  # type: ignore
                modified_date=cve.modified_date.isoformat()
                if cve.modified_date is not None
                else None,  # type: ignore
                affected_products=cve.affected_products
                if cve.affected_products is not None
                else [],  # type: ignore
            )
            response.append(cve_response)

        return response
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error in retrieving CVE: {str(e)}"
        )


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
async def check_my_vulnerabilities(current_user: dict = Depends(get_current_user)):
    """
    Check vulnerabilities for all assets of the current user
    """
    try:
        user_email = current_user.get("sub")
        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid user token")

        vulnerabilities = cve_service.check_assets_vulnerabilities(user_email)

        response = []
        for vuln in vulnerabilities:
            publish_date = vuln.get("publish_date")
            vuln_response = VulnerabilityResponse(
                asset_id=vuln.get("asset_id", 0),
                asset_name=vuln.get("asset_name", ""),
                asset_version=vuln.get("asset_version"),
                cve_id=vuln.get("cve_id", ""),
                severity=vuln.get("severity"),
                score=vuln.get("score"),
                summary=vuln.get("summary"),
                publish_date=publish_date.isoformat() if publish_date else None,
            )
            response.append(vuln_response)

        return response
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error in checking vulnerabilities: {str(e)}",
        )


@router.get("/search")
async def search_cves(
    product: str = Query(description="Product name to search"),
    version: Optional[str] = Query(
        default=None, description="Product version (optional)"
    ),
    current_user: dict = Depends(get_current_user),
):
    """
    Search CVEs for a specific product in the NIST NVD API
    """
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in CVE search: {str(e)}")
