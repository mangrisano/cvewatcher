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


def _asset(db, name="app"):
    asset = Asset(name=name, version="1.0", user_email=_OWNER)
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
