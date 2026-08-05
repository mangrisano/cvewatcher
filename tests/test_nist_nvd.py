"""Unit tests for the NIST NVD client (no network access)."""

from datetime import datetime, timezone

import httpx
import pytest

from app.services import nist_nvd
from app.services.nist_nvd import NistNvdClient, NvdUnavailableError

SAMPLE_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-02T10:00:00.000Z",
                "lastModified": "2024-01-03T11:30:00.000",
                "descriptions": [
                    {"lang": "es", "value": "Descripcion"},
                    {"lang": "en", "value": "A critical flaw in ACME Server."},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:server:*:*",
                                        "versionEndExcluding": "2.0",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:acme:os:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://example.com/advisory"},
                    {"url": ""},
                ],
            }
        }
    ]
}


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self):
        return self._json


def test_parse_cve_response_extracts_fields():
    client = NistNvdClient()
    results = client._parse_cve_response(SAMPLE_RESPONSE)

    assert len(results) == 1
    cve = results[0]
    assert cve.cve_id == "CVE-2024-0001"
    assert cve.summary == "A critical flaw in ACME Server."
    assert cve.severity == "CRITICAL"
    assert cve.score == 9.8
    # Only the vulnerable cpeMatch is kept.
    assert len(cve.affected_products) == 1
    assert cve.affected_products[0]["cpe"] == "cpe:2.3:a:acme:server:*:*"
    # Empty reference URLs are filtered out.
    assert cve.references == ["https://example.com/advisory"]
    assert cve.publish_date is not None
    assert cve.modified_date is not None


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.0, "CRITICAL"),
        (7.5, "HIGH"),
        (4.0, "MEDIUM"),
        (1.0, "LOW"),
        (0.0, "LOW"),
    ],
)
def test_severity_mapping(score, expected):
    client = NistNvdClient()
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-X",
                    "descriptions": [],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                }
            }
        ]
    }
    assert client._parse_cve_response(response)[0].severity == expected


def test_parse_datetime_handles_z_and_microseconds():
    client = NistNvdClient()
    assert client._parse_datetime("2024-01-02T10:00:00.000Z") is not None
    assert client._parse_datetime("2024-01-02T10:00:00") is not None
    assert client._parse_datetime(None) is None


def test_api_key_added_to_headers():
    client = NistNvdClient(api_key="secret-key")
    assert client.session_headers["apiKey"] == "secret-key"
    assert "apiKey" not in NistNvdClient().session_headers


def test_make_request_retries_on_rate_limit(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(status_code=429, headers={"Retry-After": "0"})
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    result = client._make_request({})

    assert calls["n"] == 2
    assert result == {"vulnerabilities": []}


def test_make_request_gives_up_after_max_retries(monkeypatch):
    def always_rate_limited(*args, **kwargs):
        return FakeResponse(status_code=429)

    monkeypatch.setattr(nist_nvd.httpx, "get", always_rate_limited)
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    with pytest.raises(Exception, match="failed after"):
        client._make_request({})


def test_make_request_retries_on_timeout(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.TimeoutException("timed out")
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    assert client._make_request({}) == {"vulnerabilities": []}
    assert calls["n"] == 2


def test_make_request_raises_unavailable_on_connection_error(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(nist_nvd.httpx, "get", boom)
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    with pytest.raises(NvdUnavailableError):
        client._make_request({})


def test_make_request_raises_unavailable_after_max_retries(monkeypatch):
    monkeypatch.setattr(
        nist_nvd.httpx, "get", lambda *a, **k: FakeResponse(status_code=503)
    )
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    with pytest.raises(NvdUnavailableError):
        # 503 raises HTTPStatusError -> wrapped as NvdUnavailableError.
        client._make_request({})


CPE_RESPONSE = {
    "products": [
        {
            "cpe": {
                "deprecated": True,
                "cpeName": "cpe:2.3:a:igor_sysoev:nginx:0.1.27:*:*:*:*:*:*:*",
                "deprecatedBy": [
                    {"cpeName": "cpe:2.3:a:nginx:nginx:0.1.27:*:*:*:*:*:*:*"}
                ],
            }
        },
        {
            "cpe": {
                "deprecated": False,
                "cpeName": "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
            }
        },
        {
            "cpe": {
                "deprecated": False,
                "cpeName": "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
            }
        },
    ]
}


def test_find_cpe_names_resolves_and_follows_deprecation(monkeypatch):
    client = NistNvdClient()
    captured = {}

    def fake_make_request(params, url=None):
        captured["url"] = url
        captured["params"] = params
        return CPE_RESPONSE

    monkeypatch.setattr(client, "_make_request", fake_make_request)

    names = client.find_cpe_names("nginx")

    # Hits the CPE dictionary endpoint, not the CVE endpoint.
    assert captured["url"] == NistNvdClient.CPE_BASE_URL
    assert captured["params"]["keywordSearch"] == "nginx"
    # Deprecated entry is replaced by its successor; duplicates collapsed.
    assert names == [
        "cpe:2.3:a:nginx:nginx:0.1.27:*:*:*:*:*:*:*",
        "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
    ]


def test_find_cpe_names_is_cached(monkeypatch):
    client = NistNvdClient()
    calls = {"n": 0}

    def fake_make_request(params, url=None):
        calls["n"] += 1
        return CPE_RESPONSE

    monkeypatch.setattr(client, "_make_request", fake_make_request)

    client.find_cpe_names("nginx")
    client.find_cpe_names("nginx")

    assert calls["n"] == 1


def test_search_cves_caches_identical_queries(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)

    client = NistNvdClient()
    client.search_cves(cpe_name="cpe:2.3:a:x:y:1.0")
    client.search_cves(cpe_name="cpe:2.3:a:x:y:1.0")

    # Second identical query is served from the cache.
    assert calls["n"] == 1


def test_search_cves_cache_expires_after_ttl(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)

    clock = {"t": 1000.0}
    monkeypatch.setattr(nist_nvd.time, "monotonic", lambda: clock["t"])

    client = NistNvdClient()
    client.search_cves(keyword="openssl")
    clock["t"] += client.CACHE_TTL_SECONDS + 1
    client.search_cves(keyword="openssl")

    assert calls["n"] == 2


def test_search_cves_buckets_date_window_by_hour(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)

    client = NistNvdClient()
    within_same_hour_a = datetime(2024, 1, 1, 10, 5, tzinfo=timezone.utc)
    within_same_hour_b = datetime(2024, 1, 1, 10, 55, tzinfo=timezone.utc)
    client.search_cves(cpe_name="cpe:2.3:a:x:y", pub_start_date=within_same_hour_a)
    client.search_cves(cpe_name="cpe:2.3:a:x:y", pub_start_date=within_same_hour_b)

    # Both windows fall in the same hour bucket -> a single request.
    assert calls["n"] == 1


def test_search_cves_use_cache_false_bypasses_read_but_refreshes(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)

    client = NistNvdClient()
    # use_cache=False always hits the API (so monitoring never misses new CVEs).
    client.search_cves(cpe_name="cpe:2.3:a:x:y", use_cache=False)
    client.search_cves(cpe_name="cpe:2.3:a:x:y", use_cache=False)
    assert calls["n"] == 2

    # ...but the fresh result still populated the cache for interactive readers.
    client.search_cves(cpe_name="cpe:2.3:a:x:y")
    assert calls["n"] == 2


def test_search_cves_uses_virtual_match_for_wildcard_version(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["params"] = params
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd.httpx, "get", fake_get)
    client = NistNvdClient()

    # Wildcard version -> virtualMatchString (cpeName would 404 on NVD).
    client.search_cves(cpe_name="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
    assert (
        captured["params"]["virtualMatchString"] == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    )
    assert "cpeName" not in captured["params"]

    # Concrete version -> exact cpeName (server-side version-range evaluation).
    client.search_cves(cpe_name="cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
    assert (
        captured["params"]["cpeName"] == "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
    )
    assert "virtualMatchString" not in captured["params"]


def test_make_request_treats_404_as_empty_not_unavailable(monkeypatch):
    monkeypatch.setattr(
        nist_nvd.httpx, "get", lambda *a, **k: FakeResponse(status_code=404)
    )
    monkeypatch.setattr(nist_nvd.time, "sleep", lambda *_: None)

    client = NistNvdClient()
    # A 404 must NOT be reported as an outage (which would surface as a 503).
    assert client._make_request({}) == {}


def test_search_cves_returns_empty_on_404(monkeypatch):
    monkeypatch.setattr(
        nist_nvd.httpx, "get", lambda *a, **k: FakeResponse(status_code=404)
    )
    client = NistNvdClient()
    assert client.search_cves(cpe_name="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*") == []


def test_find_cpe_names_empty_keyword_returns_empty():
    assert NistNvdClient().find_cpe_names("") == []
