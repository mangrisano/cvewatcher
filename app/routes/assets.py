from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.models import AssetCreate, AssetResponse
from app.database.connection import get_db
from app.database.models import Asset
from app.dependencies import get_current_user
from app.services.nist_nvd import nist_client

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
    """
    Register a new asset to monitor for CVEs.

    You can specify:
    - name: Software/hardware name (e.g., "Apache HTTP Server")
    - version: Version number (e.g., "2.4.41")
    - cpe: CPE identifier for precise matching (e.g., "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")
    - description: Optional description
    """
    try:
        # Check if asset already exists for this user
        existing = (
            db.query(Asset)
            .filter(
                Asset.name == asset_data.name,
                Asset.user_email == current_user.get("email"),
                Asset.version == asset_data.version,
            )
            .first()
        )

        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Asset '{asset_data.name}' version '{asset_data.version}' already exists",
            )

        # Create new asset
        new_asset = Asset(
            name=asset_data.name,
            version=asset_data.version,
            cpe=asset_data.cpe,
            user_email=current_user.get("email"),
            description=asset_data.description,
        )

        db.add(new_asset)
        db.commit()
        db.refresh(new_asset)

        return AssetResponse.model_validate(new_asset)

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Error creating asset")


@router.get("/assets", tags=["assets"], response_model=List[AssetResponse])
async def get_my_assets(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get all assets registered by the current user."""
    assets = db.query(Asset).filter(Asset.user_email == current_user.get("email")).all()
    return [AssetResponse.model_validate(asset) for asset in assets]


@router.get("/assets/{asset_id}", tags=["assets"], response_model=AssetResponse)
async def get_asset(
    asset_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get details of a specific asset."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("email"))
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
    """Get all CVEs affecting a specific asset."""
    # Get the asset
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("email"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        vulnerabilities = []

        # Build search queries
        search_queries = []

        asset_name = getattr(asset, "name", None)
        asset_cpe = getattr(asset, "cpe", None)
        asset_version = getattr(asset, "version", None)

        if asset_name:
            search_queries.append(asset_name)
            # Add variations
            name_lower = asset_name.lower()
            search_queries.append(name_lower.replace(" ", ""))
            search_queries.append(name_lower.replace(" ", "-"))

        if asset_cpe:
            search_queries.append(asset_cpe)

        if asset_version and asset_name:
            search_queries.append(f"{asset_name} {asset_version}")

        # Remove duplicates
        search_queries = list(set(search_queries))

        # Search for CVEs
        for query in search_queries[
            :3
        ]:  # Limit to first 3 queries to avoid too many API calls
            try:
                cves = nist_client.search_cves(keyword=query, results_per_page=50)

                for cve in cves:
                    # Check if CVE is relevant
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

        # Remove duplicates by CVE ID
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
    """Delete an asset from monitoring."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == current_user.get("email"))
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.delete(asset)
    db.commit()
