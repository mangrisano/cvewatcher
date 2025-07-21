from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.dependencies import get_current_user
from app.database import get_db, User

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
