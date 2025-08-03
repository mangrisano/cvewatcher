from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.models import UserRegistrationRequest, UserLoginRequest, RefreshTokenRequest
from app.utils.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
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
    refresh_token = create_refresh_token(data={"sub": user.email})

    return {
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
        },
    }


@router.post("/auth/refresh", tags=["auth"])
async def refresh_access_token(
    request: RefreshTokenRequest, db: Session = Depends(get_db)
):
    try:
        payload = verify_refresh_token(request.refresh_token)
        user_email = payload.get("sub")

        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        db_user = db.query(User).filter(User.email == user_email).first()
        if not db_user:
            raise HTTPException(status_code=401, detail="User not found")

        # Create new access token
        new_access_token = create_access_token(data={"sub": user_email})

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/auth/logout", tags=["auth"])
async def logout_user():
    return {"message": "Logout successful. Please discard your tokens."}
