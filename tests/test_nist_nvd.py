"""Unit tests for the NIST NVD client (no network access)."""

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from app.services import nist_nvd
from app.services.nist_nvd import NistNvdClient, NvdUnavailableError


def _as_async(fn):
    async def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


async def _no_sleep(*_):
    return None


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

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    result = asyncio.run(client._make_request({}))

    assert calls["n"] == 2
    assert result == {"vulnerabilities": []}


def test_make_request_gives_up_after_max_retries(monkeypatch):
    def always_rate_limited(*args, **kwargs):
        return FakeResponse(status_code=429)

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(always_rate_limited))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    with pytest.raises(Exception, match="failed after"):
        asyncio.run(client._make_request({}))


def test_make_request_retries_on_timeout(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.TimeoutException("timed out")
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    assert asyncio.run(client._make_request({})) == {"vulnerabilities": []}
    assert calls["n"] == 2


def test_make_request_raises_unavailable_on_connection_error(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(boom))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    with pytest.raises(NvdUnavailableError):
        asyncio.run(client._make_request({}))


def test_make_request_raises_unavailable_after_max_retries(monkeypatch):
    monkeypatch.setattr(
        nist_nvd, "_http_get", _as_async(lambda *a, **k: FakeResponse(status_code=503))
    )
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    with pytest.raises(NvdUnavailableError):
        # 503 raises HTTPStatusError -> wrapped as NvdUnavailableError.
        asyncio.run(client._make_request({}))


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

    async def fake_make_request(params, url=None):
        captured["url"] = url
        captured["params"] = params
        return CPE_RESPONSE

    monkeypatch.setattr(client, "_make_request", fake_make_request)

    names = asyncio.run(client.find_cpe_names("nginx"))

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

    async def fake_make_request(params, url=None):
        calls["n"] += 1
        return CPE_RESPONSE

    monkeypatch.setattr(client, "_make_request", fake_make_request)

    asyncio.run(client.find_cpe_names("nginx"))
    asyncio.run(client.find_cpe_names("nginx"))

    assert calls["n"] == 1


def test_search_cves_caches_identical_queries(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))

    client = NistNvdClient()
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:x:y:1.0"))
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:x:y:1.0"))

    # Second identical query is served from the cache.
    assert calls["n"] == 1


def test_search_cves_cache_expires_after_ttl(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))

    clock = {"t": 1000.0}
    monkeypatch.setattr(nist_nvd.time, "monotonic", lambda: clock["t"])

    client = NistNvdClient()
    asyncio.run(client.search_cves(keyword="openssl"))
    clock["t"] += client.CACHE_TTL_SECONDS + 1
    asyncio.run(client.search_cves(keyword="openssl"))

    assert calls["n"] == 2


def test_search_cves_buckets_date_window_by_hour(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))

    client = NistNvdClient()
    within_same_hour_a = datetime(2024, 1, 1, 10, 5, tzinfo=timezone.utc)
    within_same_hour_b = datetime(2024, 1, 1, 10, 55, tzinfo=timezone.utc)
    asyncio.run(
        client.search_cves(cpe_name="cpe:2.3:a:x:y", pub_start_date=within_same_hour_a)
    )
    asyncio.run(
        client.search_cves(cpe_name="cpe:2.3:a:x:y", pub_start_date=within_same_hour_b)
    )

    # Both windows fall in the same hour bucket -> a single request.
    assert calls["n"] == 1


def test_search_cves_use_cache_false_bypasses_read_but_refreshes(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))

    client = NistNvdClient()
    # use_cache=False always hits the API (so monitoring never misses new CVEs).
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:x:y", use_cache=False))
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:x:y", use_cache=False))
    assert calls["n"] == 2

    # ...but the fresh result still populated the cache for interactive readers.
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:x:y"))
    assert calls["n"] == 2


def test_search_cves_uses_virtual_match_for_wildcard_version(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["params"] = params
        return FakeResponse(status_code=200, json_data={"vulnerabilities": []})

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    client = NistNvdClient()

    # Wildcard version -> virtualMatchString (cpeName would 404 on NVD).
    asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"))
    assert (
        captured["params"]["virtualMatchString"] == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    )
    assert "cpeName" not in captured["params"]

    # Concrete version -> exact cpeName (server-side version-range evaluation).
    asyncio.run(
        client.search_cves(cpe_name="cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
    )
    assert (
        captured["params"]["cpeName"] == "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
    )
    assert "virtualMatchString" not in captured["params"]


def test_make_request_treats_404_as_empty_not_unavailable(monkeypatch):
    monkeypatch.setattr(
        nist_nvd, "_http_get", _as_async(lambda *a, **k: FakeResponse(status_code=404))
    )
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)

    client = NistNvdClient()
    # A 404 must NOT be reported as an outage (which would surface as a 503).
    assert asyncio.run(client._make_request({})) == {}


def test_search_cves_returns_empty_on_404(monkeypatch):
    monkeypatch.setattr(
        nist_nvd, "_http_get", _as_async(lambda *a, **k: FakeResponse(status_code=404))
    )
    client = NistNvdClient()
    assert (
        asyncio.run(client.search_cves(cpe_name="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"))
        == []
    )


def test_find_cpe_names_empty_keyword_returns_empty():
    assert asyncio.run(NistNvdClient().find_cpe_names("")) == []


def test_search_cves_rejects_date_ranges_nvd_would_refuse():
    from datetime import datetime, timedelta, timezone

    from app.services.nist_nvd import MAX_DATE_RANGE_DAYS, NistNvdClient

    end = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="cannot exceed"):
        asyncio.run(
            NistNvdClient().search_cves(
                keyword="nginx",
                pub_start_date=end - timedelta(days=MAX_DATE_RANGE_DAYS + 1),
                pub_end_date=end,
            )
        )


def test_unscored_cve_has_no_severity_or_score():
    response = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2099-1", "descriptions": [], "metrics": {}}}
        ]
    }
    cve = NistNvdClient()._parse_cve_response(response)[0]
    assert cve.severity is None
    assert cve.score is None


def _page(start, total, size):
    ids = range(start, min(start + size, total))
    return {
        "totalResults": total,
        "vulnerabilities": [
            {"cve": {"id": f"CVE-2099-{i}", "descriptions": []}} for i in ids
        ],
    }


def test_search_cves_all_pages_follows_total_results(monkeypatch):
    starts = []
    sleeps = []

    def fake_get(url, headers=None, params=None, timeout=None):
        starts.append(params["startIndex"])
        return FakeResponse(json_data=_page(params["startIndex"], 5, 2))

    async def record_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", record_sleep)
    monkeypatch.setattr(NistNvdClient, "PAGE_SIZE", 2)

    cves = asyncio.run(
        NistNvdClient().search_cves(cpe_name="cpe:2.3:a:x:y", all_pages=True)
    )

    assert starts == [0, 2, 4]
    assert [c.cve_id for c in cves] == [f"CVE-2099-{i}" for i in range(5)]
    # Keyless clients pause between pages to respect NVD's rate limit.
    assert sleeps == [NistNvdClient.KEYLESS_PAGE_DELAY_SECONDS] * 2


def test_search_cves_all_pages_stops_at_max_pages(monkeypatch, caplog):
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(json_data=_page(params["startIndex"], 100, 2))

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    monkeypatch.setattr(nist_nvd.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(NistNvdClient, "PAGE_SIZE", 2)
    monkeypatch.setattr(NistNvdClient, "MAX_PAGES", 3)

    cves = asyncio.run(
        NistNvdClient(api_key="k").search_cves(keyword="linux", all_pages=True)
    )

    assert len(cves) == 6
    assert "truncated" in caplog.text


def test_search_cves_without_all_pages_reads_one_page(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["n"] += 1
        return FakeResponse(json_data=_page(params["startIndex"], 500, 100))

    monkeypatch.setattr(nist_nvd, "_http_get", _as_async(fake_get))
    cves = asyncio.run(
        NistNvdClient().search_cves(keyword="nginx", results_per_page=100)
    )
    assert calls["n"] == 1
    assert len(cves) == 100
