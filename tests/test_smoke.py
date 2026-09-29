def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_login_and_profile(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "Password123",
        },
    )
    assert response.status_code == 200

    response = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "Password123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    token = body["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_register_rejects_short_password(client):
    response = client.post(
        "/auth/register",
        json={"username": "shorty", "email": "shorty@example.com", "password": "short"},
    )
    assert response.status_code == 422


def test_registration_gating(client, monkeypatch):
    # Ensure at least one user exists so the bootstrap allowance is consumed.
    client.post(
        "/auth/register",
        json={
            "username": "gate_seed",
            "email": "gate_seed@example.com",
            "password": "Password123",
        },
    )
    monkeypatch.setenv("REGISTRATION_ENABLED", "false")
    assert client.get("/auth/registration-status").json() == {"open": False}
    response = client.post(
        "/auth/register",
        json={
            "username": "denied",
            "email": "denied@example.com",
            "password": "Password123",
        },
    )
    assert response.status_code == 403


def test_login_with_wrong_password(client):
    client.post(
        "/auth/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "Password123",
        },
    )
    response = client.post(
        "/auth/login",
        json={"email": "bob@example.com", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_asset_crud_flow(client):
    client.post(
        "/auth/register",
        json={
            "username": "carol",
            "email": "carol@example.com",
            "password": "Password123",
        },
    )
    token = client.post(
        "/auth/login",
        json={"email": "carol@example.com", "password": "Password123"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.20.0"}
    )
    assert response.status_code == 200
    asset_id = response.json()["id"]

    # Creating the same asset twice is rejected.
    response = client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.20.0"}
    )
    assert response.status_code == 400

    response = client.get("/assets/", headers=headers)
    assert response.status_code == 200
    assert any(asset["id"] == asset_id for asset in response.json())

    response = client.patch(
        f"/assets/{asset_id}",
        headers=headers,
        json={"name": "nginx", "version": "1.21.0", "description": "web server"},
    )
    assert response.status_code == 200
    assert response.json()["version"] == "1.21.0"

    response = client.delete(f"/assets/{asset_id}", headers=headers)
    assert response.status_code == 204


def test_assets_require_authentication(client):
    response = client.get("/assets/")
    assert response.status_code in (401, 403)


def test_vulnerabilities_returns_503_when_nvd_unavailable(client, monkeypatch):
    from app.services import cve_monitoring
    from app.services.nist_nvd import NvdUnavailableError

    client.post(
        "/auth/register",
        json={
            "username": "erin",
            "email": "erin@example.com",
            "password": "Password123",
        },
    )
    token = client.post(
        "/auth/login",
        json={"email": "erin@example.com", "password": "Password123"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    asset_id = client.post(
        "/assets/", headers=headers, json={"name": "openssl"}
    ).json()["id"]

    def boom(*args, **kwargs):
        raise NvdUnavailableError("NVD down")

    monkeypatch.setattr(cve_monitoring.nist_client, "search_cves", boom)

    response = client.get(f"/assets/{asset_id}/vulnerabilities", headers=headers)
    assert response.status_code == 503
    assert "NVD" in response.json()["detail"]


def test_asset_list_pagination(client):
    client.post(
        "/auth/register",
        json={
            "username": "dave",
            "email": "dave@example.com",
            "password": "Password123",
        },
    )
    token = client.post(
        "/auth/login",
        json={"email": "dave@example.com", "password": "Password123"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(3):
        response = client.post(
            "/assets/", headers=headers, json={"name": f"pkg{i}", "version": "1.0.0"}
        )
        assert response.status_code == 200

    # limit caps the number of returned assets
    page = client.get("/assets/?limit=2&offset=0", headers=headers)
    assert page.status_code == 200
    assert len(page.json()) == 2

    # offset skips the first ones
    page2 = client.get("/assets/?limit=2&offset=2", headers=headers)
    assert page2.status_code == 200
    assert len(page2.json()) == 1

    # invalid pagination params are rejected
    assert client.get("/assets/?limit=0", headers=headers).status_code == 422
    assert client.get("/assets/?offset=-1", headers=headers).status_code == 422


def test_init_schema_follows_the_engine_when_database_url_is_unset(monkeypatch):
    import app.database as database

    called = []
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(database, "create_tables", lambda: called.append(True))

    database.init_schema()
    assert called == [True]


def _login(client, username, email):
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_days_beyond_the_nvd_window_are_rejected(client):
    headers = _login(client, "gina", "gina@example.com")
    assert client.get("/findings?days=365", headers=headers).status_code == 422
    assert client.get("/findings/export?days=121", headers=headers).status_code == 422
    assert (
        client.get("/assets/monitoring/report?days=0", headers=headers).status_code
        == 422
    )


def test_finding_status_rejects_malformed_ids(client):
    headers = _login(client, "hank", "hank@example.com")
    asset_id = client.post(
        "/assets/", headers=headers, json={"name": "django", "version": "4.0"}
    ).json()["id"]
    url = f"/assets/{asset_id}/vulnerabilities"
    body = {"status": "fixed"}

    for bad in ("<img src=x>", "CVE-2024-" + "1" * 20, "not-an-id"):
        assert (
            client.patch(f"{url}/{bad}", headers=headers, json=body).status_code == 422
        )
    for good in ("CVE-2024-12345", "GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-123"):
        assert (
            client.patch(f"{url}/{good}", headers=headers, json=body).status_code == 200
        )


def test_asset_patch_is_partial(client):
    headers = _login(client, "ivan", "ivan@example.com")
    asset = client.post(
        "/assets/",
        headers=headers,
        json={
            "name": "nginx",
            "version": "1.24.0",
            "cpe": "cpe:2.3:a:f5:nginx:1.24.0",
            "description": "edge proxy",
        },
    ).json()
    client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.25.0"}
    )
    url = f"/assets/{asset['id']}"

    updated = client.patch(url, headers=headers, json={"description": "gateway"}).json()
    assert updated["description"] == "gateway"
    assert updated["version"] == "1.24.0"
    assert updated["cpe"] == "cpe:2.3:a:f5:nginx:1.24.0"

    cleared = client.patch(url, headers=headers, json={"cpe": ""}).json()
    assert cleared["cpe"] is None

    assert client.patch(url, headers=headers, json={"name": None}).status_code == 422
    assert client.patch(url, headers=headers, json={"name": " "}).status_code == 422
    duplicate = client.patch(url, headers=headers, json={"version": "1.25.0"})
    assert duplicate.status_code == 400


def test_changing_asset_identity_drops_only_untriaged_findings(client):
    from uuid import UUID

    from app.database.connection import SessionLocal
    from app.database.models import AssetCVE, CVE

    headers = _login(client, "judy", "judy@example.com")
    asset_id = client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.20.0"}
    ).json()["id"]
    ids = {"CVE-2099-1001": "open", "CVE-2099-1002": "false_positive"}

    db = SessionLocal()
    try:
        for cve_id in ids:
            if not db.get(CVE, cve_id):
                db.add(CVE(id=cve_id))
        db.add_all(
            AssetCVE(asset_id=UUID(asset_id), cve_id=cve_id, status=status)
            for cve_id, status in ids.items()
        )
        db.commit()

        def linked():
            db.expire_all()
            rows = db.query(AssetCVE).filter(AssetCVE.asset_id == UUID(asset_id))
            return {row.cve_id: row.status for row in rows}

        url = f"/assets/{asset_id}"
        client.patch(url, headers=headers, json={"description": "edge"})
        assert linked() == ids

        client.patch(url, headers=headers, json={"version": "1.20.0"})
        assert linked() == ids

        client.patch(url, headers=headers, json={"version": "1.26.0"})
        assert linked() == {"CVE-2099-1002": "false_positive"}
    finally:
        db.query(AssetCVE).filter(AssetCVE.cve_id.in_(ids)).delete(
            synchronize_session=False
        )
        db.query(CVE).filter(CVE.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_waiting_on_nvd_does_not_block_other_requests(monkeypatch):
    import asyncio

    import httpx

    from app.main import app
    from app.services import cve_service as cve_service_module
    from app.utils.auth import create_access_token

    nvd_released = None

    async def slow_nvd(*args, **kwargs):
        await nvd_released.wait()
        return []

    monkeypatch.setattr(
        cve_service_module.nist_client, "search_cves_for_product", slow_nvd
    )
    headers = {"Authorization": f"Bearer {create_access_token({'sub': 'k@x.it'})}"}

    async def scenario():
        nonlocal nvd_released
        nvd_released = asyncio.Event()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            search = asyncio.create_task(
                c.get("/cves/search?product=nginx", headers=headers)
            )
            health = await asyncio.wait_for(c.get("/health"), timeout=2)
            nvd_released.set()
            return health.status_code, (await search).status_code

    assert asyncio.run(scenario()) == (200, 200)


def test_findings_return_503_when_nvd_is_unavailable(client, monkeypatch):
    from app.services import cve_monitoring
    from app.services.nist_nvd import NvdUnavailableError

    headers = _login(client, "kate", "kate@example.com")
    client.post("/assets/", headers=headers, json={"name": "openssl"})

    async def boom(*args, **kwargs):
        raise NvdUnavailableError("NVD down")

    monkeypatch.setattr(cve_monitoring.nist_client, "search_cves", boom)
    monkeypatch.setattr(cve_monitoring.nist_client, "find_cpe_names", boom)

    for url in ("/findings", "/findings/export"):
        response = client.get(url, headers=headers)
        assert response.status_code == 503
        assert "NVD service is currently unavailable" in response.json()["detail"]
