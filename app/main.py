import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import asynccontextmanager
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from app.config import get_settings
from app.routes.landing import router as landing_router
from app.routes.dashboard import router as dashboard_router
from app.routes.auth import router as auth_router
from app.routes.misc import router as misc_router
from app.routes.user import router as user_router
from app.routes.assets import router as assets_router
from app.routes.cves import router as cves_router
from app.routes.findings import router as findings_router
from app.database import init_schema
from app.services.nist_nvd import NvdUnavailableError
from app.services.scheduler import start_scheduler, shutdown_scheduler
from app.services.token_blocklist import BlocklistUnavailableError

logging.basicConfig(
    level=get_settings().log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CVE Watcher")
    init_schema()
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    title="CVE Watcher",
    description="A FastAPI application for monitoring CVE vulnerabilities",
    version="2.6.2",
    lifespan=lifespan,
)

_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)
# These pages load CDN assets and inline scripts, and show no user data.
_CSP_EXEMPT = {"/", "/docs", "/docs/oauth2-redirect", "/redoc"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path not in _CSP_EXEMPT:
        response.headers.setdefault("Content-Security-Policy", _CSP)
    return response


@app.exception_handler(BlocklistUnavailableError)
async def blocklist_unavailable(request: Request, exc: BlocklistUnavailableError):
    return JSONResponse(
        status_code=503,
        content={"detail": "Authentication temporarily unavailable"},
        headers={"Retry-After": "30"},
    )


@app.exception_handler(NvdUnavailableError)
async def nvd_unavailable(request: Request, exc: NvdUnavailableError):
    return JSONResponse(
        status_code=503,
        content={
            "detail": "NVD service is currently unavailable. "
            f"Please retry later. ({exc})"
        },
    )


app.include_router(landing_router)
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(misc_router)
app.include_router(user_router)
app.include_router(assets_router)
app.include_router(cves_router)
app.include_router(findings_router)

_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
