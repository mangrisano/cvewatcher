from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.models import UserRegistrationRequest, UserLoginRequest
from app.utils.auth import create_access_token, hash_password, verify_password
from app.database import get_db, User

router = APIRouter()


@router.post("/auth/register", tags=["auth"])
async def register_user(user: UserRegistrationRequest, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter((User.email == user.email) | (User.username == user.username))
        .first()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username, email=user.email, password_hash=hashed_password
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {
        "message": f"User {user.username} registered successfully",
        "email": user.email,
    }


@router.post("/auth/login", tags=["auth"])
async def login_user(user: UserLoginRequest, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(user.password, str(db_user.password_hash)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
        },
    }
