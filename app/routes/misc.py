from fastapi import APIRouter
from app.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["misc"])
async def health_check():
    return HealthResponse(status="ok")
