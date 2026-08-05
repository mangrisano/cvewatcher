"""Tests for the OSV client, Prometheus metrics and the email digest formatter."""

from types import SimpleNamespace

import httpx

from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE
from app.services import osv
from app.services.digest import _format_digest
from app.services.metrics import render_metrics
from app.services.osv import OsvClient


def test_osv_to_finding_prefers_cve_alias():
    vuln = {
        "id": "GHSA-xxxx",
        "aliases": ["CVE-2024-1234", "GHSA-xxxx"],
        "summary": "flaw",
        "published": "2024-01-01T00:00:00Z",
        "database_specific": {"severity": "MODERATE"},
    }
    finding = OsvClient._to_finding(vuln)
    assert finding["cve_id"] == "CVE-2024-1234"
    assert finding["severity"] == "MEDIUM"  # MODERATE normalised
    assert "cve.org" in finding["cve_url"]


def test_osv_to_finding_falls_back_to_osv_id():
    vuln = {"id": "GHSA-yyyy", "summary": "flaw", "aliases": []}
    finding = OsvClient._to_finding(vuln)
    assert finding["cve_id"] == "GHSA-yyyy"
    assert "osv.dev" in finding["cve_url"]


def test_osv_search_parses_and_degrades(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"vulns": [{"id": "GHSA-1", "aliases": []}]},
        )

    monkeypatch.setattr(osv.httpx, "post", fake_post)
    assert OsvClient().search("PyPI", "django", "4.0") == [
        OsvClient._to_finding({"id": "GHSA-1", "aliases": []})
    ]

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(osv.httpx, "post", boom)
    assert OsvClient().search("PyPI", "django") == []


def test_format_digest():
    link = SimpleNamespace(status="open")
    cve = SimpleNamespace(id="CVE-2024-1", severity="HIGH")
    asset = SimpleNamespace(name="nginx", version="1.24.0")
    out = _format_digest([(link, cve, asset)])
    assert "CVE-2024-1" in out
    assert "nginx v1.24.0" in out
    assert "status: open" in out


def test_render_metrics_exposes_gauges():
    db = SessionLocal()
    email = "metrics@example.com"
    ids = ["CVE-MET-1", "CVE-MET-2"]

    def _clean():
        db.query(AssetCVE).filter(AssetCVE.cve_id.in_(ids)).delete(
            synchronize_session=False
        )
        db.query(CVE).filter(CVE.id.in_(ids)).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.user_email == email).delete()
        db.commit()

    try:
        _clean()
        asset = Asset(name="nginx", version="1.0", user_email=email)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        db.add_all([CVE(id=ids[0], severity="HIGH"), CVE(id=ids[1], severity="LOW")])
        db.commit()
        db.add_all(
            [
                AssetCVE(asset_id=asset.id, cve_id=ids[0], status="open"),
                AssetCVE(asset_id=asset.id, cve_id=ids[1], status="fixed"),
            ]
        )
        db.commit()

        out = render_metrics(db)
        assert "# TYPE cvewatcher_assets_total gauge" in out
        assert "cvewatcher_findings_total" in out
        assert 'severity="HIGH"' in out
        assert 'status="fixed"' in out
    finally:
        _clean()
        db.close()
