"""Findings are stored by scans and read back from the database."""

import asyncio

import pytest

from app.database.connection import SessionLocal
from app.database.models import CVE, Asset, AssetCVE
from app.services.cve_monitoring import CVEMonitoringService
from app.services.findings_query import FindingFilters, query_findings
from app.services.sources import SourceResult

_OWNER = "store-owner@example.com"


class _Source:
    def __init__(self, findings, unavailable=False):
        self.findings = findings
        self.unavailable = unavailable

    async def search(self, asset, start, end, use_cache):
        return SourceResult([dict(f) for f in self.findings], self.unavailable)


class _Enricher:
    kev_catalog_loaded = True

    def __init__(self, kev=(), epss=None):
        self.kev = set(kev)
        self.epss = epss or {}

    async def enrich(self, findings):
        for finding in findings:
            finding["kev"] = finding["cve_id"] in self.kev
            finding["epss"] = self.epss.get(finding["cve_id"])
        return findings


def _finding(cve_id, severity="HIGH", score=7.5, published="2026-01-01T00:00:00Z"):
    return {
        "cve_id": cve_id,
        "severity": severity,
        "score": score,
        "summary": f"summary of {cve_id}",
        "publish_date": published,
        "relevance_reason": "test match",
    }


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    ids = [a.id for a in session.query(Asset).filter(Asset.user_email == _OWNER)]
    session.query(AssetCVE).filter(AssetCVE.asset_id.in_(ids)).delete(
        synchronize_session=False
    )
    session.query(Asset).filter(Asset.user_email == _OWNER).delete()
    session.query(CVE).filter(CVE.id.like("CVE-2098-%")).delete(
        synchronize_session=False
    )
    session.commit()
    session.close()


def _asset(db, name="app", ecosystem=None):
    asset = Asset(name=name, version="1.0", ecosystem=ecosystem, user_email=_OWNER)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _scan(db, asset, source, enricher=None):
    service = CVEMonitoringService(
        db, sources=[source], enricher=enricher or _Enricher()
    )
    return asyncio.run(service.monitor_asset(asset))


def _ids(db, **filters):
    page = query_findings(db, _OWNER, FindingFilters(**filters))
    return [f["cve_id"] for f in page.findings]


def test_scan_stores_everything_the_dashboard_shows(db):
    asset = _asset(db)
    enricher = _Enricher(kev={"CVE-2098-0001"}, epss={"CVE-2098-0001": 0.42})
    _scan(db, asset, _Source([_finding("CVE-2098-0001")]), enricher)

    (finding,) = query_findings(db, _OWNER).findings
    assert finding["asset_name"] == "app"
    assert finding["severity"] == "HIGH" and finding["score"] == 7.5
    assert finding["kev"] is True and finding["epss"] == 0.42
    assert finding["relevance_reason"] == "test match"
    assert finding["cve_url"].endswith("CVE-2098-0001")
    assert finding["publish_date"].startswith("2026-01-01")


def test_rescan_refreshes_cve_data(db):
    asset = _asset(db)
    _scan(db, asset, _Source([_finding("CVE-2098-0002", "MEDIUM", 5.0)]))
    _scan(db, asset, _Source([_finding("CVE-2098-0002", "CRITICAL", 9.8)]))

    (finding,) = query_findings(db, _OWNER).findings
    assert (finding["severity"], finding["score"]) == ("CRITICAL", 9.8)


def test_findings_gone_from_a_complete_scan_disappear(db):
    asset = _asset(db)
    source = _Source([_finding("CVE-2098-0003"), _finding("CVE-2098-0004")])
    _scan(db, asset, source)
    service = CVEMonitoringService(db)
    service.findings.set_status(asset.id, "CVE-2098-0004", "acknowledged", "note")

    source.findings = []
    _scan(db, asset, source)
    assert _ids(db) == []
    # The untriaged link is deleted; the triaged one is kept, hidden.
    kept = db.query(AssetCVE).filter(AssetCVE.asset_id == asset.id).all()
    assert [link.cve_id for link in kept] == ["CVE-2098-0004"]

    # If it comes back, its triage status is still there.
    source.findings = [_finding("CVE-2098-0004")]
    _scan(db, asset, source)
    (finding,) = query_findings(db, _OWNER).findings
    assert finding["status"] == "acknowledged"


def test_incomplete_scan_keeps_findings_it_could_not_see(db):
    asset = _asset(db)
    _scan(db, asset, _Source([_finding("CVE-2098-0005"), _finding("CVE-2098-0006")]))

    # One source down: what it would have reported must not vanish.
    partial = _Source([_finding("CVE-2098-0005")], unavailable=True)
    _scan(db, asset, partial)
    assert sorted(_ids(db)) == ["CVE-2098-0005", "CVE-2098-0006"]


def test_query_pages_filters_and_sorts_in_sql(db):
    asset = _asset(db)
    findings = [
        _finding(f"CVE-2098-01{i:02d}", severity, score)
        for i, (severity, score) in enumerate(
            [("CRITICAL", 9.5), ("HIGH", 7.0), ("LOW", 2.0), ("MEDIUM", 5.0)] * 3
        )
    ]
    _scan(db, asset, _Source(findings), _Enricher(kev={"CVE-2098-0102"}))

    # Default order: KEV first, then by severity.
    first = _ids(db)[:2]
    assert first[0] == "CVE-2098-0102"
    assert query_findings(db, _OWNER).findings[1]["severity"] == "CRITICAL"

    pages = [
        [f["cve_id"] for f in query_findings(db, _OWNER, limit=5, offset=o).findings]
        for o in (0, 5, 10)
    ]
    assert sorted(sum(pages, [])) == sorted(f["cve_id"] for f in findings)

    page = query_findings(db, _OWNER, FindingFilters(severity="LOW"), limit=2)
    assert page.matched == 3 and len(page.findings) == 2
    # Counts ignore the filters: they describe all active findings.
    assert page.total == 12 and page.by_severity["LOW"] == 3 and page.kev == 1

    scores = [
        f["score"]
        for f in query_findings(
            db, _OWNER, FindingFilters(sort="score", descending=False)
        ).findings
    ]
    assert scores == sorted(scores)
    assert _ids(db, search="0105") == ["CVE-2098-0105"]
    assert query_findings(db, _OWNER, limit=0).findings == []


def test_findings_tell_apart_the_same_package_in_two_ecosystems(db):
    _scan(db, _asset(db, "linux", "Debian:13"), _Source([_finding("CVE-2098-0250")]))
    _scan(db, _asset(db, "linux", "Debian:12"), _Source([_finding("CVE-2098-0250")]))
    found = query_findings(db, _OWNER).findings
    assert sorted(f["asset_ecosystem"] for f in found) == ["Debian:12", "Debian:13"]
    searched = query_findings(db, _OWNER, FindingFilters(search="debian:13")).findings
    assert [f["asset_ecosystem"] for f in searched] == ["Debian:13"]


def test_search_treats_wildcards_literally(db):
    _scan(db, _asset(db, name="a_b 50%"), _Source([_finding("CVE-2098-0200")]))
    _scan(db, _asset(db, name="axb 500"), _Source([_finding("CVE-2098-0201")]))
    assert _ids(db, search="a_b") == ["CVE-2098-0200"]
    assert _ids(db, search="50%") == ["CVE-2098-0200"]


def test_suppressed_findings_are_hidden_unless_asked(db):
    asset = _asset(db)
    _scan(db, asset, _Source([_finding("CVE-2098-0300")]))
    CVEMonitoringService(db).findings.set_status(
        asset.id, "CVE-2098-0300", "false_positive", None
    )
    assert _ids(db) == []
    assert _ids(db, include_suppressed=True) == ["CVE-2098-0300"]


def test_findings_api_pages_and_reports_scan_state(client):
    from fastapi import Depends

    from app.database import get_db
    from app.dependencies import get_monitoring_service
    from app.main import app

    email = "pager@example.com"
    client.post(
        "/auth/register",
        json={"username": "pager", "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/assets/", headers=headers, json={"name": "lib", "version": "1"})

    before = client.get("/findings", headers=headers).json()
    assert before["unscanned_assets"] == 1 and before["last_scan"] is None

    source = _Source([_finding(f"CVE-2098-04{i:02d}") for i in range(30)])
    app.dependency_overrides[get_monitoring_service] = lambda db=Depends(get_db): (
        CVEMonitoringService(db, sources=[source], enricher=_Enricher())
    )
    try:
        client.get("/findings?refresh=true&limit=0", headers=headers)
    finally:
        app.dependency_overrides.pop(get_monitoring_service)

    body = client.get("/findings?limit=10&offset=20", headers=headers).json()
    assert body["total"] == body["matched"] == 30
    assert len(body["findings"]) == 10
    assert body["unscanned_assets"] == 0
    assert body["last_scan"].endswith(("+00:00", "Z"))
    assert client.get("/findings?sort=bogus", headers=headers).status_code == 422
    assert client.get("/findings?limit=501", headers=headers).status_code == 422


def test_new_assets_are_scanned_in_the_background(client, monkeypatch):
    from app.routes import assets as asset_routes

    scanned = []

    async def fake_scan(asset_ids):
        scanned.extend(asset_ids)

    monkeypatch.setenv("SCAN_NEW_ASSETS", "true")
    monkeypatch.setattr(asset_routes, "scan_in_background", fake_scan)
    email = "bgscan@example.com"
    client.post(
        "/auth/register",
        json={"username": "bgscan", "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post("/assets/", headers=headers, json={"name": "bg"}).json()
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "a", "purl": "pkg:pypi/bg-a@1.0"}],
    }
    client.post("/assets/import-sbom", headers=headers, json=sbom)

    assert str(scanned[0]) == created["id"]
    assert len(scanned) == 2


def test_overlapping_scans_of_one_asset_run_one_at_a_time(db):
    asset = _asset(db)
    active = {"now": 0, "max": 0}

    class _Slow(_Source):
        async def search(self, asset, start, end, use_cache):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            await asyncio.sleep(0.05)
            active["now"] -= 1
            return await super().search(asset, start, end, use_cache)

    source = _Slow([_finding("CVE-2098-0500")])
    other = SessionLocal()
    try:
        first = CVEMonitoringService(db, sources=[source], enricher=_Enricher())
        second = CVEMonitoringService(other, sources=[source], enricher=_Enricher())
        twin = other.get(Asset, asset.id)

        async def both():
            return await asyncio.gather(
                first.monitor_asset(asset), second.monitor_asset(twin)
            )

        results = asyncio.run(both())
    finally:
        other.close()

    assert active["max"] == 1
    # The second scan sees the first one's finding: a single "new" alert.
    assert sum(len(r["new_vulnerabilities"]) for r in results) == 1


def test_a_scan_that_cannot_be_stored_sends_no_alerts(db, monkeypatch):
    from app.services.alerts import extract_alerts

    asset = _asset(db)
    service = CVEMonitoringService(
        db, sources=[_Source([_finding("CVE-2098-0600")])], enricher=_Enricher()
    )
    monkeypatch.setattr(service.findings, "save", lambda: False)

    result = asyncio.run(service.monitor_asset(asset))
    assert result["status"] == "error"
    assert extract_alerts({"asset_results": [result]}) == []


def _headers(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_live_lookups_are_limited_per_user(client, monkeypatch):
    from app.utils import rate_limit
    from app.utils.rate_limit import InMemoryRateLimiter

    monkeypatch.setattr(
        rate_limit,
        "live_lookup_rate_limiter",
        InMemoryRateLimiter(max_attempts=1, window_seconds=3600),
    )
    headers = _headers(client, "quota")
    other = _headers(client, "quota2")

    assert client.get("/findings?refresh=true", headers=headers).status_code == 200
    limited = client.get("/findings?refresh=true", headers=headers)
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) > 0
    assert client.get("/cves/search?product=x", headers=headers).status_code == 429
    assert (
        client.post("/assets/monitoring/scan-all", headers=headers).status_code == 429
    )
    # Reading stored findings is never limited, and the quota is per user.
    assert client.get("/findings", headers=headers).status_code == 200
    assert client.get("/findings?refresh=true", headers=other).status_code == 200


def test_asset_and_all_findings_endpoints_read_the_database(client):
    headers = _headers(client, "dbreader")
    asset_id = client.post(
        "/assets/", headers=headers, json={"name": "reader-lib", "version": "1"}
    ).json()["id"]
    db = SessionLocal()
    try:
        asset = db.get(Asset, __import__("uuid").UUID(asset_id))
        _scan(db, asset, _Source([_finding("CVE-2098-0700", "CRITICAL", 9.1)]))
    finally:
        db.close()

    body = client.get(f"/assets/{asset_id}/vulnerabilities", headers=headers).json()
    assert [v["cve_id"] for v in body["vulnerabilities"]] == ["CVE-2098-0700"]
    only_low = client.get(
        f"/assets/{asset_id}/vulnerabilities?severity=LOW", headers=headers
    ).json()
    assert only_low["total_vulnerabilities"] == 0
    everything = client.get("/cves/vulnerabilities", headers=headers).json()
    assert [v["cve_id"] for v in everything] == ["CVE-2098-0700"]
    summary = client.get("/findings?limit=0", headers=headers).json()
    assert summary["total_assets"] == 1 and summary["total"] == 1
