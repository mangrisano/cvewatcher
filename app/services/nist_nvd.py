import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Any

import httpx
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class NvdUnavailableError(Exception):
    """Raised when the NVD API cannot be reached or keeps failing."""


@dataclass
class CVEData:
    cve_id: str
    summary: str
    severity: Optional[str]
    score: Optional[float]
    publish_date: Optional[datetime]
    modified_date: Optional[datetime]
    affected_products: list[dict[str, Any]]
    references: list[str]


class NistNvdClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    MAX_RETRIES = 3
    BACKOFF_BASE_SECONDS = 6
    # Short-lived cache so repeated identical queries (e.g. re-opening an asset
    # or toggling the dashboard severity filter) do not re-hit the NVD API.
    CACHE_TTL_SECONDS = int(os.getenv("NVD_CACHE_TTL_SECONDS", "600"))

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session_headers = {"User-Agent": "CVEWatcher/1.0 (Python)"}
        if api_key:
            self.session_headers["apiKey"] = api_key
        self._cpe_cache: dict[str, list[str]] = {}
        self._search_cache: dict[tuple, tuple[float, list["CVEData"]]] = {}

    def _make_request(
        self, params: dict[str, Any], url: Optional[str] = None
    ) -> dict[str, Any]:
        last_error: Optional[Exception] = None
        for attempt in range(self.MAX_RETRIES):
            try:
                response = httpx.get(
                    url or self.BASE_URL,
                    headers=self.session_headers,
                    params=params,
                    timeout=30,
                )
                if response.status_code in (403, 429):
                    retry_after = response.headers.get("Retry-After")
                    wait = (
                        float(retry_after)
                        if retry_after
                        else self.BACKOFF_BASE_SECONDS * (attempt + 1)
                    )
                    logger.warning(
                        f"NIST API rate limited (HTTP {response.status_code}), "
                        f"retrying in {wait}s (attempt {attempt + 1}/{self.MAX_RETRIES})"
                    )
                    last_error = Exception(f"Rate limited: HTTP {response.status_code}")
                    time.sleep(wait)
                    continue
                # A 404 means "no data for this query" (e.g. a CPE not in the
                # dictionary), not that NVD is down: return an empty result set
                # instead of raising, so it never surfaces as a 503.
                if response.status_code == 404:
                    return {}
                response.raise_for_status()
                return response.json()
            except httpx.TimeoutException as e:
                last_error = e
                wait = self.BACKOFF_BASE_SECONDS * (attempt + 1)
                logger.warning(
                    f"NIST API timeout (attempt {attempt + 1}/{self.MAX_RETRIES}), "
                    f"retrying in {wait}s: {e}"
                )
                time.sleep(wait)
                continue
            except httpx.HTTPError as e:
                logger.error(f"NIST API connection error: {e}")
                raise NvdUnavailableError(f"Connection error: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Error in parsing JSON: {e}")
                raise Exception(f"Invalid API response: {e}")
        raise NvdUnavailableError(
            f"NIST API request failed after {self.MAX_RETRIES} attempts: {last_error}"
        )

    def search_cves(
        self,
        cpe_name: Optional[str] = None,
        keyword: Optional[str] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        mod_start_date: Optional[datetime] = None,
        mod_end_date: Optional[datetime] = None,
        results_per_page: int = 20,
        start_index: int = 0,
        use_cache: bool = True,
    ) -> list[CVEData]:
        cache_key = self._search_cache_key(
            cpe_name,
            keyword,
            pub_start_date,
            pub_end_date,
            mod_start_date,
            mod_end_date,
            results_per_page,
            start_index,
        )
        now = time.monotonic()
        if use_cache:
            cached = self._search_cache.get(cache_key)
            if cached is not None and now - cached[0] < self.CACHE_TTL_SECONDS:
                return cached[1]

        params: dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }

        if cpe_name:
            # NVD's exact ``cpeName`` filter 404s on a wildcard version; use the
            # pattern-matching ``virtualMatchString`` for versionless CPEs.
            if self._has_wildcard_version(cpe_name):
                params["virtualMatchString"] = cpe_name
            else:
                params["cpeName"] = cpe_name
        if keyword:
            params["keywordSearch"] = keyword
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_start_date:
            params["modStartDate"] = mod_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_end_date:
            params["modEndDate"] = mod_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        try:
            response = self._make_request(params)
            cves = self._parse_cve_response(response)
        except Exception as e:
            logger.error(f"Error in CVE search: {e}")
            raise

        self._search_cache[cache_key] = (now, cves)
        return cves

    @staticmethod
    def _has_wildcard_version(cpe_name: str) -> bool:
        """True when a CPE 2.3 name has an unspecified (wildcard) version."""
        parts = cpe_name.split(":")
        return len(parts) <= 5 or parts[5] in ("*", "-", "")

    @staticmethod
    def _search_cache_key(
        cpe_name: Optional[str],
        keyword: Optional[str],
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        mod_start_date: Optional[datetime],
        mod_end_date: Optional[datetime],
        results_per_page: int,
        start_index: int,
    ) -> tuple:
        # Date windows are bucketed to the hour so time-windowed queries (e.g.
        # "last 30 days", whose bounds shift by microseconds each call) still
        # share a cache entry.
        def bucket(dt: Optional[datetime]) -> Optional[str]:
            if dt is None:
                return None
            return dt.replace(minute=0, second=0, microsecond=0).isoformat()

        return (
            cpe_name,
            keyword,
            bucket(pub_start_date),
            bucket(pub_end_date),
            bucket(mod_start_date),
            bucket(mod_end_date),
            results_per_page,
            start_index,
        )

    def get_recent_cves(
        self, days: int = 7, cpe_name: Optional[str] = None
    ) -> list[CVEData]:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        return self.search_cves(
            cpe_name=cpe_name,
            pub_start_date=start_date,
            pub_end_date=end_date,
            results_per_page=2000,
        )

    def search_cves_for_product(
        self, product_name: str, version: Optional[str] = None
    ) -> list[CVEData]:
        keyword = product_name
        if version:
            keyword = f"{product_name} {version}"

        return self.search_cves(keyword=keyword, results_per_page=100)

    def find_cpe_names(self, keyword: str, limit: int = 500) -> list[str]:
        """Resolve a product name to canonical CPE names via the NVD CPE API.

        Returns the ``cpeName`` strings matching ``keyword`` so an asset that
        only has a product name can still be searched precisely (by
        ``cpeName``) instead of via the keyword search capped at 100 hits.
        Deprecated dictionary entries are replaced by their ``deprecatedBy``
        successors so historical vendors (e.g. ``igor_sysoev`` -> ``nginx``)
        resolve to the current canonical names. Cached per keyword.
        """
        if not keyword:
            return []
        cache_key = keyword.strip().lower()
        if cache_key in self._cpe_cache:
            return self._cpe_cache[cache_key]

        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 10000)}
        response = self._make_request(params, url=self.CPE_BASE_URL)

        names: list[str] = []
        seen: set[str] = set()
        for product in response.get("products", []):
            cpe = product.get("cpe", {})
            if cpe.get("deprecated"):
                candidates = [
                    dep.get("cpeName")
                    for dep in cpe.get("deprecatedBy", [])
                    if dep.get("cpeName")
                ]
            else:
                candidates = [cpe.get("cpeName")] if cpe.get("cpeName") else []
            for name in candidates:
                if name not in seen:
                    seen.add(name)
                    names.append(name)

        self._cpe_cache[cache_key] = names
        return names

    def _parse_cve_response(self, response: dict[str, Any]) -> list[CVEData]:
        cves = []

        try:
            vulnerabilities = response.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "")
                descriptions = cve_item.get("descriptions", [])
                summary = next(
                    (
                        desc.get("value", "")
                        for desc in descriptions
                        if desc.get("lang") == "en"
                    ),
                    "",
                )

                metrics = cve_item.get("metrics", {})
                score = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric = metrics.get(key)
                    if metric:
                        cvss_data = metric[0].get("cvssData", {})
                        score = cvss_data.get("baseScore", 0.0)
                        if score:
                            break

                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                publish_date = self._parse_datetime(cve_item.get("published"))
                modified_date = self._parse_datetime(cve_item.get("lastModified"))

                affected_products = [
                    {
                        "cpe": match.get("criteria", ""),
                        "version_start": match.get("versionStartIncluding"),
                        "version_end": match.get("versionEndExcluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                    }
                    for config in cve_item.get("configurations", [])
                    for node in config.get("nodes", [])
                    for match in node.get("cpeMatch", [])
                    if match.get("vulnerable", False)
                ]

                references = [
                    ref.get("url", "")
                    for ref in cve_item.get("references", [])
                    if ref.get("url", "")
                ]

                cve_data = CVEData(
                    cve_id=cve_id,
                    summary=summary,
                    severity=severity,
                    score=score,
                    publish_date=publish_date,
                    modified_date=modified_date,
                    affected_products=affected_products,
                    references=references,
                )

                cves.append(cve_data)

        except Exception as e:
            logger.error(f"Error parsing CVE response: {e}")
            raise Exception(f"Error parsing: {e}")

        return cves

    def _parse_datetime(self, date_string: Optional[str]) -> Optional[datetime]:
        if not date_string:
            return None

        try:
            if date_string.endswith("Z"):
                date_string = date_string[:-1] + "+00:00"

            try:
                return datetime.fromisoformat(date_string)
            except ValueError:
                if "+" in date_string:
                    date_string = date_string.split("+")[0]
                elif date_string.count(":") == 3:
                    date_string = date_string.rsplit(":", 1)[0]

                if "." in date_string:
                    return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f")
                else:
                    return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S")

        except ValueError as e:
            logger.warning(f"Unable to parse date '{date_string}': {e}")
            return None


nist_client = NistNvdClient(api_key=os.getenv("NVD_API_KEY"))
