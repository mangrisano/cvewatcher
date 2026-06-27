"""Unit tests for version-aware CVE relevance matching."""

import asyncio
from datetime import datetime
from types import SimpleNamespace

from app.services.cve_monitoring import CVEMonitoringService


def _service():
    # The matcher methods do not touch the DB, so a dummy db is fine.
    return CVEMonitoringService(db=None)


def _asset(name="nginx", version=None):
    return SimpleNamespace(name=name, version=version, cpe=None)


def _cve(summary="", affected_products=None):
    return SimpleNamespace(
        summary=summary,
        affected_products=affected_products or [],
    )


def test_version_in_range_is_relevant():
    svc = _service()
    cve = _cve(
        summary="A flaw in nginx",
        affected_products=[
            {
                "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "version_start": "1.20.0",
                "version_end": "1.25.0",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is True


def test_version_below_range_is_not_relevant():
    svc = _service()
    # "nginx before 1.13.6": vulnerable only for versions < 1.13.6.
    cve = _cve(
        summary="nginx before 1.13.6 has a buffer overflow",
        affected_products=[
            {
                "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": "1.13.6",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is False


def test_exact_cpe_version_match():
    svc = _service()
    cve = _cve(
        affected_products=[
            {
                "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": None,
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is True
    assert svc._is_relevant_to_asset(cve, _asset(version="1.23.0")) is False


def test_third_party_product_with_version_is_filtered_out():
    svc = _service()
    # CVE only mentions nginx in text; affected CPE is a different product.
    cve = _cve(
        summary="Pascom Cloud Phone System used in NGINX deployments",
        affected_products=[
            {
                "cpe": "cpe:2.3:a:pascom:cloud_phone_system:7.0:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": "7.20",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    # The CVE has CPE data but none reference nginx -> not relevant, even though
    # the summary mentions nginx. This is the Step B product-identity filter.
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is False


def test_third_party_product_without_version_is_filtered_out():
    svc = _service()
    cve = _cve(
        summary="Authelia, a portal often deployed behind nginx, has a flaw",
        affected_products=[
            {
                "cpe": "cpe:2.3:a:authelia:authelia:4.0:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": "4.30",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    # Even without an asset version, a CVE whose CPEs are all foreign products
    # is filtered out when CPE data is present.
    assert svc._is_relevant_to_asset(cve, _asset(version=None)) is False


def test_no_version_keeps_name_based_relevance():
    svc = _service()
    cve = _cve(summary="A flaw in nginx web server")
    assert svc._is_relevant_to_asset(cve, _asset(version=None)) is True


def test_similar_named_product_is_not_matched():
    svc = _service()
    # "nginx_proxy_manager" is a different product and must not match "nginx".
    cve = _cve(
        summary="jc21 Nginx Proxy Manager before 2.9.17 allows XSS",
        affected_products=[
            {
                "cpe": "cpe:2.3:a:jc21:nginx_proxy_manager:2.9.0:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": "2.9.17",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is False


def test_unparseable_asset_version_is_not_dropped():
    svc = _service()
    cve = _cve(
        affected_products=[
            {
                "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "version_start": "1.0.0",
                "version_end": "2.0.0",
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="weird-build")) is True


def test_full_cpe_pads_partial_cpe():
    # A partial CPE is padded to the 13-component CPE 2.3 form NVD requires.
    assert (
        CVEMonitoringService._full_cpe("cpe:2.3:a:f5:nginx:1.24.0")
        == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    )


def test_full_cpe_keeps_complete_cpe():
    full = "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert CVEMonitoringService._full_cpe(full) == full


def test_full_cpe_rejects_non_cpe_values():
    assert CVEMonitoringService._full_cpe(None) is None
    assert CVEMonitoringService._full_cpe("nginx 1.24.0") is None
    assert CVEMonitoringService._full_cpe("") is None


def test_asset_with_cpe_uses_precise_nvd_lookup(monkeypatch):
    # When an asset declares a CPE, NVD's cpeName filter is used directly and
    # the imprecise keyword search must NOT run.
    svc = _service()
    calls = {}

    def fake_search(*, cpe_name=None, keyword=None, **kwargs):
        calls["cpe_name"] = cpe_name
        calls["keyword"] = keyword
        return [
            SimpleNamespace(
                cve_id="CVE-2024-7347",
                summary="nginx mp4 module issue",
                severity="HIGH",
                score=7.5,
                publish_date=datetime(2024, 8, 14),
                modified_date=datetime(2024, 8, 15),
            )
        ]

    monkeypatch.setattr(svc.nist_client, "search_cves", fake_search)

    asset = SimpleNamespace(
        name="nginx",
        version="1.24.0",
        cpe="cpe:2.3:a:f5:nginx:1.24.0",
    )
    result = asyncio.run(svc._get_asset_vulnerabilities(asset))

    assert calls["cpe_name"] == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert calls["keyword"] is None
    assert [v["cve_id"] for v in result] == ["CVE-2024-7347"]
    assert result[0]["relevance_reason"].startswith("NVD matched CPE")

    svc = _service()
    cve = _cve(
        affected_products=[
            {
                "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "version_start": None,
                "version_end": None,
                "version_start_excluding": None,
                "version_end_including": None,
            }
        ],
    )
    assert svc._is_relevant_to_asset(cve, _asset(version="1.24.0")) is True
