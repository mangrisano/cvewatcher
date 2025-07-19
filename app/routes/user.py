from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.dependencies import get_current_user
from app.database import get_db, Asset, User
from app.models import AssetCreate, AssetResponse

router = APIRouter()

@router.get("/user", tags=["user"])
async def get_user_profile(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    user_email = current_user.get("sub")
    db_user = db.query(User).filter(User.email == user_email).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "created_at": db_user.created_at,
    }

@router.get("/user/assets", tags=["user"], response_model=list[AssetResponse])
async def get_user_assets(
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    user_email = current_user.get("sub")
    assets = db.query(Asset).filter(Asset.user_email == user_email).all()
    return assets

@router.post("/user/assets", tags=["user"], response_model=AssetResponse)
async def create_user_asset(
    data: AssetCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = current_user.get("sub")

    db_asset = Asset(
        name=data.name,
        version=data.version,
        cpe=data.cpe,
        user_email=user_email,
        description=data.description,
    )

    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)

    return db_asset

@router.delete("/user/assets/{asset_id}", tags=["user"])
async def delete_user_asset(
    asset_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = current_user.get("sub")

    db_asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.user_email == user_email)
        .first()
    )

    if not db_asset:
        raise HTTPException(
            status_code=404, detail="Asset not found or not owned by user"
        )

    db.delete(db_asset)
    db.commit()

    return {"message": "Asset deleted successfully"}
