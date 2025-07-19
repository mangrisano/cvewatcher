from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from app.models import AssetCreate, AssetResponse
from app.database.connection import get_db
from app.database.models import Asset
from app.dependencies import get_current_user
from app.services.nist_nvd import nist_client
from app.services.cve_monitoring import CVEMonitoringService

router = APIRouter()


@router.post(
    "/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["assets"],
)
async def register_asset(
    asset_data: AssetCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
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
            user_email=user_email,
            description=asset_data.description if asset_data.description else None,
        )

        db.add(new_asset)
        db.commit()
        db.refresh(new_asset)

        return AssetResponse.model_validate(new_asset)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Asset creation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating asset: {str(e)}")


@router.get("/assets", tags=["assets"], response_model=List[AssetResponse])
async def get_my_assets(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    assets = db.query(Asset).filter(Asset.user_email == current_user.get("sub")).all()
    return [AssetResponse.model_validate(asset) for asset in assets]


@router.get("/assets/{asset_id}", tags=["assets"], response_model=AssetResponse)
async def get_asset(
    asset_id: int,
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


@router.get("/assets/{asset_id}/vulnerabilities", tags=["assets"])
async def get_asset_vulnerabilities(
    asset_id: int,
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
        vulnerabilities = []

        search_queries = []

        asset_name = getattr(asset, "name", None)
        asset_cpe = getattr(asset, "cpe", None)
        asset_version = getattr(asset, "version", None)

        if asset_name:
            search_queries.append(asset_name)
            name_lower = asset_name.lower()
            search_queries.append(name_lower.replace(" ", ""))
            search_queries.append(name_lower.replace(" ", "-"))

        if asset_cpe:
            search_queries.append(asset_cpe)

        if asset_version and asset_name:
            search_queries.append(f"{asset_name} {asset_version}")

        search_queries = list(set(search_queries))

        for query in search_queries[:3]:
            try:
                cves = nist_client.search_cves(keyword=query, results_per_page=50)

                for cve in cves:
                    if asset_name and asset_name.lower() in cve.summary.lower():
                        vulnerabilities.append(
                            {
                                "cve_id": cve.cve_id,
                                "summary": cve.summary,
                                "severity": cve.severity,
                                "score": cve.score,
                                "publish_date": cve.publish_date.isoformat()
                                if cve.publish_date
                                else None,
                                "relevance_reason": f"Matches asset name '{asset_name}'",
                            }
                        )

            except Exception as e:
                print(f"Error searching for {query}: {e}")
                continue

        unique_cves = {}
        for vuln in vulnerabilities:
            cve_id = vuln["cve_id"]
            if cve_id not in unique_cves:
                unique_cves[cve_id] = vuln

        final_vulnerabilities = list(unique_cves.values())

        return {
            "asset": AssetResponse.model_validate(asset),
            "vulnerabilities": final_vulnerabilities,
            "total_vulnerabilities": len(final_vulnerabilities),
            "search_queries_used": search_queries[:3],
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving vulnerabilities: {str(e)}"
        )


@router.delete(
    "/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["assets"]
)
async def delete_asset(
    asset_id: int,
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


@router.get("/assets/{asset_id}/monitor", tags=["assets"])
async def monitor_asset_cves(
    asset_id: int,
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

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error monitoring asset: {str(e)}")


@router.get("/monitoring/report", tags=["assets"])
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

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error generating report: {str(e)}"
        )


@router.post("/monitoring/scan-all", tags=["assets"])
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
            "timestamp": datetime.utcnow().isoformat(),
            "user_email": current_user.get("sub"),
            "total_assets_scanned": len(user_assets),
            "asset_results": [],
        }

        for asset in user_assets:
            result = await monitoring_service._monitor_single_asset(asset)
            scan_results["asset_results"].append(result)

        return scan_results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning assets: {str(e)}")
