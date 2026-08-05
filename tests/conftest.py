import os
import tempfile

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
# Keep the suite offline: enrichment (CISA KEV / FIRST.org EPSS) is opt-in here.
os.environ.setdefault("ENRICH_ENABLED", "false")
# Tests share one database and register many users, so keep registration open.
os.environ.setdefault("REGISTRATION_ENABLED", "true")
os.environ.setdefault("REGISTER_MAX_ATTEMPTS", "1000")

from fastapi.testclient import TestClient  # noqa: E402

from app.database import create_tables  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    create_tables()
    yield


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


def pytest_sessionfinish(session, exitstatus):
    try:
        os.close(_db_fd)
    except OSError:
        pass
    if os.path.exists(_db_path):
        os.remove(_db_path)
