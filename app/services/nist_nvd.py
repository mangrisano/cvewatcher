import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from urllib.parse import urlencode
import urllib.request
import urllib.error
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session_headers = {"User-Agent": "CVEWatcher/1.0 (Python)"}
        if api_key:
            self.session_headers["apiKey"] = api_key

    def _make_request(self, params: dict[str, Any]) -> dict[str, Any]:
        query_string = urlencode(params)
        url = f"{self.BASE_URL}?{query_string}"

        request = urllib.request.Request(url, headers=self.session_headers)

        try:
            with urllib.request.urlopen(request) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {response.reason}")

                data = json.loads(response.read().decode())
                return data

        except urllib.error.URLError as e:
            logger.error(f"NIST API connection error: {e}")
            raise Exception(f"Connection error: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error in parsing JSON: {e}")
            raise Exception(f"Invalid API response: {e}")

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
    ) -> list[CVEData]:
        params: dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }

        if cpe_name:
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
            return self._parse_cve_response(response)
        except Exception as e:
            logger.error(f"Error in CVE search: {e}")
            raise

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
                date_string = date_string[:-1]
            elif "+" in date_string:
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


nist_client = NistNvdClient()
