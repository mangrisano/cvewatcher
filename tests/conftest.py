import os
import tempfile

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


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
