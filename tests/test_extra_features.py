"""Tests for the OSV client, Prometheus metrics and the email digest formatter."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE
from app.services import matching, osv
from app.services.digest import _format_digest
from app.services.metrics import render_metrics
from app.services.osv import OsvClient, OsvError, normalize_ecosystem


def _as_async(fn):
    async def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


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


def test_osv_to_finding_derives_score_and_band_from_cvss_vector():
    vuln = {
        "id": "GHSA-zzzz",
        "aliases": [],
        "summary": "flaw",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}
        ],
    }
    finding = OsvClient._to_finding(vuln)
    assert finding["score"] == 5.3
    assert finding["severity"] == "MEDIUM"  # derived from score, no GHSA band


def test_osv_to_finding_keeps_ghsa_band_but_scores_from_vector():
    vuln = {
        "id": "GHSA-aaaa",
        "aliases": ["CVE-2024-9999"],
        "database_specific": {"severity": "HIGH"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        ],
    }
    finding = OsvClient._to_finding(vuln)
    assert finding["severity"] == "HIGH"
    assert finding["score"] == 7.5


def test_osv_to_finding_rejects_unknown_severity_text():
    vuln = {
        "id": "GHSA-bbbb",
        "aliases": [],
        "database_specific": {"severity": "<img src=x onerror=alert(1)>"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        ],
    }
    assert OsvClient._to_finding(vuln)["severity"] == "HIGH"  # band from score
    del vuln["severity"]
    assert OsvClient._to_finding(vuln)["severity"] is None


def test_finding_richness_lets_scored_duplicate_win_merge():
    poor = {"cve_id": "CVE-1", "severity": None, "score": None}
    rich = {"cve_id": "CVE-1", "severity": "HIGH", "score": 7.5}
    ordered = sorted([rich, poor], key=matching.finding_richness)
    # Richest sorts last, so the dict-based dedup keeps it.
    assert ordered[-1] is rich
    merged = {v["cve_id"]: v for v in ordered}
    assert merged["CVE-1"]["score"] == 7.5


def test_osv_search_parses_and_raises_on_failure(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"vulns": [{"id": "GHSA-1", "aliases": []}]},
        )

    monkeypatch.setattr(osv, "_http_post", _as_async(fake_post))
    assert asyncio.run(OsvClient().search("PyPI", "django", "4.0")) == [
        OsvClient._to_finding({"id": "GHSA-1", "aliases": []})
    ]

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(osv, "_http_post", _as_async(boom))
    with pytest.raises(OsvError):
        asyncio.run(OsvClient().search("PyPI", "django"))


def test_osv_search_raises_when_osv_rejects_the_query(monkeypatch):
    def rejected(url, json=None, timeout=None):
        request = httpx.Request("POST", url)
        response = httpx.Response(400, request=request)
        return SimpleNamespace(raise_for_status=response.raise_for_status)

    monkeypatch.setattr(osv, "_http_post", _as_async(rejected))
    with pytest.raises(OsvError):
        asyncio.run(OsvClient().search("Debain:13", "linux"))


def test_osv_source_reports_a_failed_query_as_unavailable():
    from app.services.sources import OsvSource

    class DownOsvClient:
        async def search(self, ecosystem, name, version):
            raise OsvError("down")

    asset = SimpleNamespace(name="linux", version="6.12.110-1", ecosystem="Debian:13")
    result = asyncio.run(OsvSource(DownOsvClient()).search(asset, None, None, True))
    assert result.findings == []
    assert result.unavailable


@pytest.mark.parametrize(
    "value, expected",
    [
        ("PyPI", "PyPI"),
        ("pypi", "PyPI"),
        ("debian:13", "Debian:13"),
        (" Ubuntu:24.04:LTS ", "Ubuntu:24.04:LTS"),
        ("red hat:enterprise_linux:9", "Red Hat:enterprise_linux:9"),
        ("crates.io", "crates.io"),
    ],
)
def test_normalize_ecosystem_uses_osv_spelling(value, expected):
    assert normalize_ecosystem(value) == expected


@pytest.mark.parametrize("value", ["Debain:13", "arch", ":13", "pip"])
def test_normalize_ecosystem_rejects_unknown_names(value):
    with pytest.raises(ValueError, match="Unknown ecosystem"):
        normalize_ecosystem(value)


def test_osv_search_follows_page_tokens(monkeypatch):
    pages = {
        None: {"vulns": [{"id": "A"}], "next_page_token": "t1"},
        "t1": {"vulns": [{"id": "B"}], "next_page_token": "t2"},
        "t2": {"vulns": [{"id": "C"}]},
    }
    tokens = []

    def fake_post(url, json=None, timeout=None):
        token = json.get("page_token")
        tokens.append(token)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: pages[token])

    monkeypatch.setattr(osv, "_http_post", _as_async(fake_post))
    found = asyncio.run(OsvClient().search("Debian:13", "linux", "6.12.110-1"))
    assert [f["cve_id"] for f in found] == ["A", "B", "C"]
    assert tokens == [None, "t1", "t2"]


def test_osv_search_stops_at_max_pages(monkeypatch):
    calls = []

    def endless(url, json=None, timeout=None):
        calls.append(1)
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"vulns": [{"id": f"X-{len(calls)}"}], "next_page_token": "t"},
        )

    monkeypatch.setattr(osv, "_http_post", _as_async(endless))
    found = asyncio.run(OsvClient().search("Debian:13", "linux"))
    assert len(calls) == osv.MAX_PAGES
    assert len(found) == osv.MAX_PAGES


def test_osv_to_finding_reads_cve_from_debian_upstream():
    vuln = {"id": "DEBIAN-CVE-2026-80521", "upstream": ["CVE-2026-80521"]}
    finding = OsvClient._to_finding(vuln)
    assert finding["cve_id"] == "CVE-2026-80521"
    assert finding["cve_url"].endswith("CVE-2026-80521")
    assert "DEBIAN-CVE-2026-80521" in finding["relevance_reason"]


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


def test_osv_source_applies_the_publication_window():
    from datetime import datetime, timezone

    from app.services.sources import OsvSource

    class FakeOsvClient:
        async def search(self, ecosystem, name, version):
            return [
                {"cve_id": "OLD", "publish_date": "2019-03-01T00:00:00Z"},
                {"cve_id": "RECENT", "publish_date": "2026-09-20T08:30:00.123456789Z"},
                {"cve_id": "NAIVE", "publish_date": "2026-09-21T00:00:00"},
                {"cve_id": "UNDATED", "publish_date": None},
            ]

    source = OsvSource(FakeOsvClient())
    asset = SimpleNamespace(name="django", version="3.2", ecosystem="PyPI")
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    end = datetime(2026, 9, 29, tzinfo=timezone.utc)

    windowed = asyncio.run(source.search(asset, start, end, True))
    assert [f["cve_id"] for f in windowed.findings] == ["RECENT", "NAIVE"]

    # No window (days=0 = all time): nothing is dropped, undated included.
    everything = asyncio.run(source.search(asset, None, None, True))
    assert len(everything.findings) == 4
