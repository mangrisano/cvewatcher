import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from enum import StrEnum
from app.models import (
    AssetCreate,
    AssetResponse,
    AssetVulnerabilitiesResponse,
    FindingStatusResponse,
    FindingStatusUpdate,
    VulnerabilityResponse,
)
from app.database.connection import get_db
from app.database.models import Asset
from app.dependencies import get_current_user
from app.services.cve_monitoring import CVEMonitoringService
from app.services.nist_nvd import NvdUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])


class SeverityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@router.post("/", response_model=AssetResponse)
async def create_asset(
    asset_data: AssetCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssetResponse:
    try:
        user_email = current_user.get("sub")
        existing = (
            db.query(Asset)
            .filter(
                Asset.name == asset_data.name,
                Asset.user_email == user_email,
                Asset.version == asset_data.version,
            )
            .first()
        )

        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Asset '{asset_data.name}' version '{asset_data.version}' already exists",
            )

        new_asset = Asset(
            name=asset_data.name,
            version=asset_data.version if asset_data.version else None,
            cpe=asset_data.cpe if asset_data.cpe else None,
            ecosystem=asset_data.ecosystem if asset_data.ecosystem else None,
            user_email=user_email,
            description=asset_data.description if asset_data.description else None,
        )

        db.add(new_asset)
        db.commit()
        db.refresh(new_asset)

        return AssetResponse.model_validate(new_asset)

    except HTTPException:
        raise
    except Exception:
        logger.exception("Asset creation error")
        raise HTTPException(status_code=500, detail="Error creating asset")


@router.get("/", response_model=list[AssetResponse])
async def get_my_assets(
    limit: int = Query(default=50, ge=1, le=100, description="Max assets to return"),
    offset: int = Query(default=0, ge=0, description="Number of assets to skip"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    assets = (
        db.query(Asset)
        .filter(Asset.user_email == current_user.get("sub"))
        .order_by(Asset.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [AssetResponse.model_validate(asset) for asset in assets]


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}/vulnerabilities", response_model=AssetVulnerabilitiesResponse)
async def get_asset_vulnerabilities(
    asset_id: UUID,
    days: int = Query(
        default=0,
        ge=0,
        description="Only CVEs published in the last N days; 0 = all time",
    ),
    severity: SeverityLevel | None = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(
            Asset.id == asset_id,
            Asset.user_email == current_user.get("sub"),
        )
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        monitoring_service = CVEMonitoringService(db)
        asset_response = AssetResponse.model_validate(asset)

        vulnerabilities = await monitoring_service._get_asset_vulnerabilities(
            asset_response,
            days=days,
            severity_filter=severity.value if severity else None,
        )

        return AssetVulnerabilitiesResponse(
            asset=asset_response,
            vulnerabilities=[VulnerabilityResponse(**vuln) for vuln in vulnerabilities],
            total_vulnerabilities=len(vulnerabilities),
            days_searched=days,
        )

    except NvdUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NVD service is currently unavailable. Please retry later. ({e})",
        )
    except Exception:
        logger.exception("Error retrieving vulnerabilities for asset %s", asset_id)
        raise HTTPException(status_code=500, detail="Error retrieving vulnerabilities")


@router.patch(
    "/{asset_id}/vulnerabilities/{cve_id}", response_model=FindingStatusResponse
)
async def set_vulnerability_status(
    asset_id: UUID,
    cve_id: str,
    update: FindingStatusUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    service = CVEMonitoringService(db)
    return service.set_finding_status(asset, cve_id, update.status.value, update.notes)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    asset_data: AssetCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    for key, value in asset_data.model_dump().items():
        setattr(asset, key, value)

    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.delete(asset)
    db.commit()


@router.get("/{asset_id}/monitor")
async def monitor_asset_cves(
    asset_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("sub"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        monitoring_service = CVEMonitoringService(db)
        result = await monitoring_service._monitor_single_asset(asset)

        return {
            "message": f"Monitoring completed for asset '{asset.name}'",
            "monitoring_result": result,
        }

    except Exception:
        logger.exception("Error monitoring asset %s", asset_id)
        raise HTTPException(status_code=500, detail="Error monitoring asset")


@router.get("/monitoring/report")
async def get_monitoring_report(
    days: int = 7,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        monitoring_service = CVEMonitoringService(db)
        user_email = current_user.get("sub") or ""
        report = await monitoring_service.get_monitoring_report(
            user_email=user_email, days=days
        )
        return report

    except Exception:
        logger.exception("Error generating monitoring report")
        raise HTTPException(status_code=500, detail="Error generating report")


@router.post("/monitoring/scan-all")
async def scan_all_assets(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        monitoring_service = CVEMonitoringService(db)

        user_assets = (
            db.query(Asset).filter(Asset.user_email == current_user.get("sub")).all()
        )

        if not user_assets:
            return {"message": "No assets found to monitor"}

        scan_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_email": current_user.get("sub"),
            "total_assets_scanned": len(user_assets),
            "asset_results": [],
        }

        for asset in user_assets:
            result = await monitoring_service._monitor_single_asset(asset)
            scan_results["asset_results"].append(result)

        return scan_results

    except Exception:
        logger.exception("Error scanning assets")
        raise HTTPException(status_code=500, detail="Error scanning assets")
