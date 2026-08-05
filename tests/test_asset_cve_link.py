"""Integration tests for the asset<->CVE association (no tenant data leak)."""

import asyncio

from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE
from app.services import cve_monitoring
from app.services.cve_monitoring import CVEMonitoringService

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

        svc = CVEMonitoringService(db)
        vuln = {
            "cve_id": _CVE,
            "summary": "test",
            "severity": "HIGH",
            "score": 7.5,
            "publish_date": None,
        }
        asyncio.run(svc._store_cve_for_asset(vuln, asset))

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
        found = svc._existing_cve_ids_for_asset(asset, [_CVE, "CVE-2099-9999"])
        assert found == {_CVE}

        # Storing the same finding again is idempotent (no duplicate link).
        asyncio.run(svc._store_cve_for_asset(vuln, asset))
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

        svc = CVEMonitoringService(db)
        vuln = {"cve_id": _CVE, "summary": "t", "severity": "LOW", "score": 1.0}
        asyncio.run(svc._store_cve_for_asset(vuln, mine))

        # The other asset is not linked, even for the same shared CVE.
        assert svc._existing_cve_ids_for_asset(other, [_CVE]) == set()
        assert svc._existing_cve_ids_for_asset(mine, [_CVE]) == {_CVE}
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
    assert cve_monitoring._nvd_concurrency_limit() == 3
    monkeypatch.setenv("NVD_MAX_CONCURRENCY", "7")
    assert cve_monitoring._nvd_concurrency_limit() == 7


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

        monkeypatch.setattr(svc, "_get_asset_vulnerabilities", fake_get)

        out = asyncio.run(svc.get_user_vulnerabilities(_EMAIL))

        assert {v["cve_id"] for v in out} == {"CVE-nginx", "CVE-openssl"}
        # Each finding is tagged with its originating asset.
        assert {v["asset_name"] for v in out} == {"nginx", "openssl"}
    finally:
        db.query(Asset).filter(Asset.user_email == _EMAIL).delete()
        db.commit()
        db.close()
