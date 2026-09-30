import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from enum import StrEnum
from app.models import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    AssetVulnerabilitiesResponse,
    FindingStatusResponse,
    FindingStatusUpdate,
    VulnerabilityResponse,
)
from app.database.connection import get_db
from app.database.models import Asset
from app.dependencies import (
    get_current_user,
    get_findings_repository,
    get_monitoring_service,
    get_owned_asset,
)
from app.services.alerts import deliver_alerts, extract_alerts
from app.services.cve_monitoring import CVEMonitoringService
from app.services.findings_repository import FindingRepository
from app.services.nist_nvd import MAX_DATE_RANGE_DAYS, NvdUnavailableError
from app.services.notifications import build_notifiers_from_env

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])

# CVE ids plus OSV ids (GHSA-…, PYSEC-…, GO-…, RUSTSEC-…); 20 = cves.id column size.
_FINDING_ID_PATTERN = r"^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9-]+$"

# Fields that decide which CVEs match an asset.
_IDENTITY_FIELDS = ("name", "version", "cpe", "ecosystem")


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
async def get_asset(asset: Asset = Depends(get_owned_asset)):
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}/vulnerabilities", response_model=AssetVulnerabilitiesResponse)
async def get_asset_vulnerabilities(
    days: int = Query(
        default=0,
        ge=0,
        le=MAX_DATE_RANGE_DAYS,
        description="Only CVEs published in the last N days; 0 = all time",
    ),
    severity: SeverityLevel | None = None,
    asset: Asset = Depends(get_owned_asset),
    monitoring_service: CVEMonitoringService = Depends(get_monitoring_service),
):
    try:
        asset_response = AssetResponse.model_validate(asset)

        vulnerabilities = await monitoring_service.find_vulnerabilities(
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

    except NvdUnavailableError:
        raise
    except Exception:
        logger.exception("Error retrieving vulnerabilities for asset %s", asset.id)
        raise HTTPException(status_code=500, detail="Error retrieving vulnerabilities")


@router.patch(
    "/{asset_id}/vulnerabilities/{cve_id}", response_model=FindingStatusResponse
)
async def set_vulnerability_status(
    update: FindingStatusUpdate,
    cve_id: str = Path(max_length=20, pattern=_FINDING_ID_PATTERN),
    asset: Asset = Depends(get_owned_asset),
    findings: FindingRepository = Depends(get_findings_repository),
):
    return findings.set_status(asset.id, cve_id, update.status.value, update.notes)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_data: AssetUpdate,
    asset: Asset = Depends(get_owned_asset),
    db: Session = Depends(get_db),
    findings: FindingRepository = Depends(get_findings_repository),
):
    changes = {
        key: value or None
        for key, value in asset_data.model_dump(exclude_unset=True).items()
    }
    name = changes.get("name", asset.name)
    version = changes.get("version", asset.version)
    duplicate = (
        db.query(Asset)
        .filter(
            Asset.id != asset.id,
            Asset.user_email == asset.user_email,
            Asset.name == name,
            Asset.version == version,
        )
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=400,
            detail=f"Asset '{name}' version '{version}' already exists",
        )

    identity_changed = any(
        key in _IDENTITY_FIELDS and getattr(asset, key) != value
        for key, value in changes.items()
    )
    for key, value in changes.items():
        setattr(asset, key, value)

    if identity_changed:
        # Untriaged findings belonged to the old identity; the next monitoring
        # cycle re-links those that still apply. Triaged ones keep their status.
        findings.drop_untriaged(asset.id)

    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset: Asset = Depends(get_owned_asset),
    db: Session = Depends(get_db),
):
    db.delete(asset)
    db.commit()


@router.get("/{asset_id}/monitor")
async def monitor_asset_cves(
    asset: Asset = Depends(get_owned_asset),
    db: Session = Depends(get_db),
    monitoring_service: CVEMonitoringService = Depends(get_monitoring_service),
):
    try:
        result = await monitoring_service.monitor_asset(asset)
        await _send_alerts(db, [result])

        return {
            "message": f"Monitoring completed for asset '{asset.name}'",
            "monitoring_result": result,
        }

    except Exception:
        logger.exception("Error monitoring asset %s", asset.id)
        raise HTTPException(status_code=500, detail="Error monitoring asset")


@router.get("/monitoring/report")
async def get_monitoring_report(
    days: int = Query(default=7, ge=1, le=MAX_DATE_RANGE_DAYS),
    current_user: dict = Depends(get_current_user),
    monitoring_service: CVEMonitoringService = Depends(get_monitoring_service),
):
    try:
        user_email = current_user.get("sub") or ""
        report = await monitoring_service.get_monitoring_report(
            user_email=user_email, days=days
        )
        return report

    except NvdUnavailableError:
        raise
    except Exception:
        logger.exception("Error generating monitoring report")
        raise HTTPException(status_code=500, detail="Error generating report")


@router.post("/monitoring/scan-all")
async def scan_all_assets(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    monitoring_service: CVEMonitoringService = Depends(get_monitoring_service),
):
    try:
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
            result = await monitoring_service.monitor_asset(asset)
            scan_results["asset_results"].append(result)
        await _send_alerts(db, scan_results["asset_results"])

        return scan_results

    except Exception:
        logger.exception("Error scanning assets")
        raise HTTPException(status_code=500, detail="Error scanning assets")


async def _send_alerts(db: Session, asset_results: list[dict]) -> None:
    # A scan records new findings as seen: alert now or the scheduler never will.
    await deliver_alerts(
        db,
        extract_alerts({"asset_results": asset_results}),
        build_notifiers_from_env(),
    )
