"""Tests for the KEV/EPSS enrichment service (network fully mocked)."""

import httpx
import pytest

from app.services import enrichment
from app.services.enrichment import EnrichmentService


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError("error")


@pytest.fixture(autouse=True)
def _enable_enrichment(monkeypatch):
    monkeypatch.setenv("ENRICH_ENABLED", "true")


def test_kev_ids_parses_and_caches(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        return FakeResponse(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2021-1"},
                    {"cveID": "cve-2021-2"},
                    {"notACve": "x"},
                ]
            }
        )

    monkeypatch.setattr(enrichment.httpx, "get", fake_get)
    service = EnrichmentService()

    assert service.kev_ids() == {"CVE-2021-1", "CVE-2021-2"}
    # Second call is served from cache (no extra HTTP request).
    assert service.kev_ids() == {"CVE-2021-1", "CVE-2021-2"}
    assert calls["n"] == 1


def test_kev_ids_degrades_to_empty_on_failure(monkeypatch):
    def boom(url, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(enrichment.httpx, "get", boom)
    service = EnrichmentService()
    assert service.kev_ids() == set()


def test_epss_scores_parses_and_caches(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        return FakeResponse(
            {
                "data": [
                    {"cve": "CVE-2021-1", "epss": "0.97"},
                    {"cve": "CVE-2021-2", "epss": "0.10"},
                ]
            }
        )

    monkeypatch.setattr(enrichment.httpx, "get", fake_get)
    service = EnrichmentService()

    scores = service.epss_scores(["CVE-2021-1", "CVE-2021-2"])
    assert scores == {"CVE-2021-1": 0.97, "CVE-2021-2": 0.10}
    # Cached: asking again does not trigger another request.
    service.epss_scores(["CVE-2021-1"])
    assert calls["n"] == 1


def test_enrich_adds_kev_and_epss(monkeypatch):
    def fake_get(url, **kwargs):
        if "known_exploited" in url:
            return FakeResponse({"vulnerabilities": [{"cveID": "CVE-2021-1"}]})
        return FakeResponse({"data": [{"cve": "CVE-2021-1", "epss": "0.5"}]})

    monkeypatch.setattr(enrichment.httpx, "get", fake_get)
    service = EnrichmentService()

    findings = [
        {"cve_id": "CVE-2021-1"},
        {"cve_id": "CVE-2021-2"},
    ]
    service.enrich(findings)

    assert findings[0]["kev"] is True
    assert findings[0]["epss"] == 0.5
    assert findings[1]["kev"] is False
    assert findings[1]["epss"] is None


def test_enrich_disabled_sets_defaults_without_network(monkeypatch):
    monkeypatch.setenv("ENRICH_ENABLED", "false")

    def boom(url, **kwargs):
        raise AssertionError("network must not be touched when disabled")

    monkeypatch.setattr(enrichment.httpx, "get", boom)
    service = EnrichmentService()

    findings = [{"cve_id": "CVE-2021-1"}]
    service.enrich(findings)
    assert findings[0]["kev"] is False
    assert findings[0]["epss"] is None
