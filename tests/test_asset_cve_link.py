"""Integration tests for the asset<->CVE association (no tenant data leak)."""

import asyncio

from app.config import get_settings
from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE
from app.models import AssetResponse
from app.services import nist_nvd, sources
from app.services.cve_monitoring import CVEMonitoringService
from app.services.findings_repository import FindingRepository

_EMAIL = "linktest@example.com"
_CVE = "CVE-2099-0001"


def _cleanup(db):
    db.query(AssetCVE).filter(AssetCVE.cve_id == _CVE).delete()
    db.query(CVE).filter(CVE.id == _CVE).delete()
    db.query(Asset).filter(Asset.user_email == _EMAIL).delete()
    db.commit()


def test_store_cve_links_asset_without_tenant_data():
    db = SessionLocal()
    try:
        _cleanup(db)
        asset = Asset(name="nginx", version="1.24.0", user_email=_EMAIL)
        db.add(asset)
        db.commit()
        db.refresh(asset)

        repo = FindingRepository(db)
        vuln = {
            "cve_id": _CVE,
            "summary": "test",
            "severity": "HIGH",
            "score": 7.5,
            "publish_date": None,
        }
        repo.link(asset.id, vuln)

        # The shared CVE row carries no tenant data.
        cve = db.query(CVE).filter(CVE.id == _CVE).first()
        assert cve is not None
        assert cve.affected_products in (None, [])

        # The association links the asset to the CVE.
        link = (
            db.query(AssetCVE)
            .filter(AssetCVE.asset_id == asset.id, AssetCVE.cve_id == _CVE)
            .first()
        )
        assert link is not None

        # The existing-ids lookup finds only linked candidates.
        found = set(repo.links(asset.id, [_CVE, "CVE-2099-9999"]))
        assert found == {_CVE}

        # Storing the same finding again is idempotent (no duplicate link).
        repo.link(asset.id, vuln)
        links = db.query(AssetCVE).filter(AssetCVE.cve_id == _CVE).all()
        assert len(links) == 1
    finally:
        _cleanup(db)
        db.close()


def test_existing_ids_are_scoped_per_asset():
    db = SessionLocal()
    try:
        _cleanup(db)
        mine = Asset(name="nginx", version="1.24.0", user_email=_EMAIL)
        other = Asset(name="nginx", version="1.24.0", user_email="other@example.com")
        db.add_all([mine, other])
        db.commit()
        db.refresh(mine)
        db.refresh(other)

        repo = FindingRepository(db)
        vuln = {"cve_id": _CVE, "summary": "t", "severity": "LOW", "score": 1.0}
        repo.link(mine.id, vuln)

        # The other asset is not linked, even for the same shared CVE.
        assert set(repo.links(other.id, [_CVE])) == set()
        assert set(repo.links(mine.id, [_CVE])) == {_CVE}
    finally:
        db.query(AssetCVE).filter(AssetCVE.cve_id == _CVE).delete()
        db.query(CVE).filter(CVE.id == _CVE).delete()
        db.query(Asset).filter(
            Asset.user_email.in_([_EMAIL, "other@example.com"])
        ).delete()
        db.commit()
        db.close()


def test_nvd_concurrency_limit(monkeypatch):
    monkeypatch.delenv("NVD_MAX_CONCURRENCY", raising=False)
    # No API key in the test env -> small default fan-out.
    assert sources.nvd_concurrency_limit(nist_nvd.nist_client) == 3
    monkeypatch.setenv("NVD_MAX_CONCURRENCY", "7")
    get_settings.cache_clear()
    assert sources.nvd_concurrency_limit(nist_nvd.nist_client) == 7


def test_get_user_vulnerabilities_aggregates_across_assets(monkeypatch):
    db = SessionLocal()
    try:
        db.query(Asset).filter(Asset.user_email == _EMAIL).delete()
        db.commit()
        a1 = Asset(name="nginx", version="1.24.0", user_email=_EMAIL)
        a2 = Asset(name="openssl", version="3.0.0", user_email=_EMAIL)
        db.add_all([a1, a2])
        db.commit()
        db.refresh(a1)
        db.refresh(a2)

        svc = CVEMonitoringService(db)

        async def fake_get(
            asset_response, days=0, severity_filter=None, use_cache=True
        ):
            return [{"cve_id": f"CVE-{asset_response.name}", "severity": "HIGH"}]

        monkeypatch.setattr(svc, "find_vulnerabilities", fake_get)

        out = asyncio.run(svc.get_user_vulnerabilities(_EMAIL))

        assert {v["cve_id"] for v in out} == {"CVE-nginx", "CVE-openssl"}
        # Each finding is tagged with its originating asset.
        assert {v["asset_name"] for v in out} == {"nginx", "openssl"}
    finally:
        db.query(Asset).filter(Asset.user_email == _EMAIL).delete()
        db.commit()
        db.close()


def test_set_and_attach_finding_status():
    db = SessionLocal()
    try:
        _cleanup(db)
        asset = Asset(name="nginx", version="1.24.0", user_email=_EMAIL)
        db.add(asset)
        db.commit()
        db.refresh(asset)

        svc = CVEMonitoringService(db)
        repo = svc.findings

        # Setting a status on a not-yet-persisted CVE creates a stub CVE + link.
        link = repo.set_status(asset.id, _CVE, "false_positive", "not exploitable")
        assert link.status == "false_positive"
        assert link.notes == "not exploitable"
        assert db.query(CVE).filter(CVE.id == _CVE).first() is not None

        # The status is attached to findings (default 'open' when no link).
        findings = [{"cve_id": _CVE}, {"cve_id": "CVE-2099-9999"}]
        svc._attach_triage_status(AssetResponse.model_validate(asset), findings)
        assert findings[0]["status"] == "false_positive"
        assert findings[1]["status"] == "open"

        # Updating the status is idempotent on the same (asset, cve).
        repo.set_status(asset.id, _CVE, "fixed", None)
        link2 = (
            db.query(AssetCVE)
            .filter(AssetCVE.asset_id == asset.id, AssetCVE.cve_id == _CVE)
            .first()
        )
        assert link2.status == "fixed"
        assert link2.notes is None
        assert db.query(AssetCVE).filter(AssetCVE.cve_id == _CVE).count() == 1
    finally:
        _cleanup(db)
        db.close()


def _asset_response(name="django"):
    from datetime import datetime, timezone
    from uuid import uuid4

    return AssetResponse(
        id=uuid4(),
        name=name,
        user_email=_EMAIL,
        created_at=datetime.now(timezone.utc),
    )


def test_severity_filter_tolerates_findings_without_severity():
    db = SessionLocal()
    try:

        class FixedSource:
            async def search(self, asset, start, end, use_cache):
                return sources.SourceResult(
                    [
                        {"cve_id": "GHSA-aaaa-bbbb-cccc", "severity": None},
                        {"cve_id": "CVE-2099-0002", "severity": "HIGH"},
                    ]
                )

        svc = CVEMonitoringService(db, sources=[FixedSource()])

        out = asyncio.run(
            svc.find_vulnerabilities(_asset_response(), severity_filter="HIGH")
        )
        assert [v["cve_id"] for v in out] == ["CVE-2099-0002"]
    finally:
        db.close()


def test_monitor_all_assets_survives_findings_without_severity(monkeypatch):
    from types import SimpleNamespace

    asset = SimpleNamespace(name="django", version="4.0")
    db = SimpleNamespace(query=lambda model: SimpleNamespace(all=lambda: [asset]))
    svc = CVEMonitoringService(db)

    async def monitor(a):
        return {"new_vulnerabilities": [{"cve_id": "GHSA-x", "severity": None}]}

    monkeypatch.setattr(svc, "monitor_asset", monitor)

    results = asyncio.run(svc.monitor_all_assets())
    assert "error" not in results
    assert results["summary"]["new_vulnerabilities"] == 1


def test_findings_from_all_sources_are_merged():
    class FixedSource:
        def __init__(self, findings, unavailable=False):
            self.result = sources.SourceResult(findings, unavailable)

        async def search(self, asset, start, end, use_cache):
            return self.result

    svc = CVEMonitoringService(
        None,
        sources=[
            FixedSource([{"cve_id": "CVE-2099-0010", "severity": None}]),
            FixedSource(
                [
                    {"cve_id": "CVE-2099-0010", "severity": "HIGH", "score": 7.5},
                    {"cve_id": "GHSA-aaaa-bbbb-cccc", "severity": "LOW"},
                ]
            ),
        ],
    )
    out = asyncio.run(svc.find_vulnerabilities(_asset_response()))

    # One entry per id; the scored duplicate wins the merge.
    assert {v["cve_id"]: v["severity"] for v in out} == {
        "CVE-2099-0010": "HIGH",
        "GHSA-aaaa-bbbb-cccc": "LOW",
    }


def test_unavailable_source_with_no_findings_raises():
    import pytest

    from app.services.nist_nvd import NvdUnavailableError

    class DownSource:
        async def search(self, asset, start, end, use_cache):
            return sources.SourceResult(unavailable=True)

    svc = CVEMonitoringService(None, sources=[DownSource()])
    with pytest.raises(NvdUnavailableError):
        asyncio.run(svc.find_vulnerabilities(_asset_response()))


def test_monitoring_report_uses_the_matching_engine():
    db = SessionLocal()
    email = "report@example.com"
    try:
        db.query(Asset).filter(Asset.user_email == email).delete()
        db.commit()
        db.add_all(
            [
                Asset(name="nginx", version="1.24.0", user_email=email),
                Asset(name="openssl", version="3.0.0", user_email=email),
            ]
        )
        db.commit()

        seen_windows = []

        class FixedSource:
            async def search(self, asset, start, end, use_cache):
                seen_windows.append((end - start).days)
                shared = {"cve_id": "CVE-2099-0100", "severity": "LOW"}
                own = {
                    "cve_id": f"CVE-2099-{asset.name}",
                    "severity": "CRITICAL" if asset.name == "openssl" else "HIGH",
                    "publish_date": "2099-01-01T00:00:00",
                }
                return sources.SourceResult([own, shared])

        svc = CVEMonitoringService(db, sources=[FixedSource()])
        report = asyncio.run(svc.get_monitoring_report(email, days=7))

        assert seen_windows == [7, 7]
        # One entry per CVE even when it affects several assets, highest first.
        assert [v["cve_id"] for v in report["recent_vulnerabilities"]] == [
            "CVE-2099-openssl",
            "CVE-2099-nginx",
            "CVE-2099-0100",
        ]
        assert report["vulnerability_summary"] == {
            "total_recent": 3,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 1,
        }
        assert report["total_assets"] == 2
    finally:
        db.query(Asset).filter(Asset.user_email == email).delete()
        db.commit()
        db.close()
