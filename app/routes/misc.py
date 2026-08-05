from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models import HealthResponse
from app.services.metrics import render_metrics

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["misc"])
async def health_check():
    return HealthResponse(status="ok")


@router.get("/metrics", tags=["misc"])
async def metrics(db: Session = Depends(get_db)):
    return Response(
        content=render_metrics(db),
        media_type="text/plain; version=0.0.4",
    )
