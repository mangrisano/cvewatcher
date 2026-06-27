import logging
import os

from fastapi import FastAPI
from fastapi.concurrency import asynccontextmanager
from app.routes.landing import router as landing_router
from app.routes.dashboard import router as dashboard_router
from app.routes.auth import router as auth_router
from app.routes.misc import router as misc_router
from app.routes.user import router as user_router
from app.routes.assets import router as assets_router
from app.routes.cves import router as cves_router
from app.database import create_tables
from app.services.scheduler import start_scheduler, shutdown_scheduler

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CVE Watcher")
    create_tables()
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    title="CVE Watcher",
    description="A FastAPI application for monitoring CVE vulnerabilities",
    version="0.4.1",
    lifespan=lifespan,
)

app.include_router(landing_router)
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(misc_router)
app.include_router(user_router)
app.include_router(assets_router)
app.include_router(cves_router)
