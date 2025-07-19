from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.models import AssetResponse
from app.database import get_db, Asset

router = APIRouter()


@router.get("/assets", tags=["assets"], response_model=list[AssetResponse])
async def get_all_assets(db: Session = Depends(get_db)):
    """Get all public assets - could be filtered later for public visibility"""
    assets = db.query(Asset).all()
    return assets


@router.get("/assets/{asset_id}", tags=["assets"], response_model=AssetResponse)
async def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get a specific asset by ID"""
    db_asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return db_asset
