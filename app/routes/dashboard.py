from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

# Single-page dashboard; markup/styles/scripts live under app/static.
_INDEX = Path(__file__).resolve().parent.parent / "static" / "index.html"


@router.get("/dashboard", response_class=FileResponse, tags=["dashboard"])
async def dashboard_page() -> FileResponse:
    return FileResponse(str(_INDEX))
