"""OSV.dev client: vulnerabilities for a package in a given ecosystem.

NVD/CPE matching is weak for language-package dependencies (npm, PyPI, Go, …);
OSV.dev covers those ecosystems well. This is a best-effort secondary source:
any failure returns an empty list so it never breaks a lookup.
"""

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# GHSA uses "MODERATE"; normalise to CVE Watcher's severity vocabulary.
_SEVERITY_MAP = {"MODERATE": "MEDIUM"}


class OsvClient:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def search(
        self, ecosystem: str, name: str, version: Optional[str] = None
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version
        try:
            response = httpx.post(OSV_QUERY_URL, json=body, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("OSV query failed for %s/%s: %s", ecosystem, name, e)
            return []
        return [self._to_finding(vuln) for vuln in payload.get("vulns", [])]

    @staticmethod
    def _to_finding(vuln: dict[str, Any]) -> dict[str, Any]:
        osv_id = vuln.get("id", "")
        aliases = vuln.get("aliases") or []
        cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

        raw_severity = (vuln.get("database_specific") or {}).get("severity")
        severity = None
        if raw_severity:
            severity = _SEVERITY_MAP.get(raw_severity.upper(), raw_severity.upper())

        is_cve = cve_id.startswith("CVE-")
        cve_url = (
            f"https://www.cve.org/CVERecord?id={cve_id}"
            if is_cve
            else f"https://osv.dev/vulnerability/{osv_id}"
        )
        summary = vuln.get("summary") or (vuln.get("details") or "")[:300]
        return {
            "cve_id": cve_id,
            "summary": summary,
            "severity": severity,
            "score": None,
            "publish_date": vuln.get("published"),
            "modified_date": vuln.get("modified"),
            "relevance_reason": f"OSV.dev match ({osv_id})",
            "cve_url": cve_url,
        }


osv_client = OsvClient()
