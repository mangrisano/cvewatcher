from fastapi import FastAPI
from fastapi.concurrency import asynccontextmanager
from app.routes.auth import router as auth_router
from app.routes.misc import router as misc_router
from app.routes.user import router as user_router
from app.routes.assets import router as assets_router
from app.routes.cves import router as cves_router
from app.database import create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="CVE Watcher",
    description="A FastAPI application for monitoring CVE vulnerabilities",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(misc_router)
app.include_router(user_router)
app.include_router(assets_router)
app.include_router(cves_router)
