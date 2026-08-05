"""OSV.dev client: vulnerabilities for a package in a given ecosystem.

NVD/CPE matching is weak for language-package dependencies (npm, PyPI, Go, …);
OSV.dev covers those ecosystems well. This is a best-effort secondary source:
any failure returns an empty list so it never breaks a lookup.
"""

import logging
from typing import Any, Optional

import httpx
from cvss import CVSS2, CVSS3, CVSS4

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# GHSA uses "MODERATE"; normalise to CVE Watcher's severity vocabulary.
_SEVERITY_MAP = {"MODERATE": "MEDIUM"}

# Prefer the newest CVSS version when an advisory carries several vectors.
_CVSS_TYPE_PREFERENCE = ("CVSS_V4", "CVSS_V3", "CVSS_V2")


def _best_cvss_vector(entries: Optional[list[dict[str, Any]]]) -> Optional[str]:
    """Pick the highest-version CVSS vector from an OSV ``severity`` array.

    OSV stores the vector string under the (confusingly named) ``score`` key.
    """
    if not entries:
        return None
    by_type = {
        (e.get("type") or "").upper(): e.get("score") for e in entries if e.get("score")
    }
    for cvss_type in _CVSS_TYPE_PREFERENCE:
        if by_type.get(cvss_type):
            return by_type[cvss_type]
    return next(iter(by_type.values()), None)


def _cvss_base_score(vector: str) -> Optional[float]:
    try:
        if vector.startswith("CVSS:4"):
            metric = CVSS4(vector)
        elif vector.startswith("CVSS:3"):
            metric = CVSS3(vector)
        else:  # CVSS v2 vectors carry no "CVSS:" prefix
            metric = CVSS2(vector)
        base = metric.base_score
        return float(base) if base is not None else None
    except Exception as e:  # malformed vector: stay best-effort
        logger.debug("Could not parse CVSS vector %r: %s", vector, e)
        return None


def _band_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return None


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

        # Score from the CVSS vector; band from the explicit GHSA severity when
        # present, otherwise derived from the computed score.
        vector = _best_cvss_vector(vuln.get("severity"))
        score = _cvss_base_score(vector) if vector else None
        raw_severity = (vuln.get("database_specific") or {}).get("severity")
        if raw_severity:
            severity = _SEVERITY_MAP.get(raw_severity.upper(), raw_severity.upper())
        else:
            severity = _band_from_score(score)

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
            "score": score,
            "publish_date": vuln.get("published"),
            "modified_date": vuln.get("modified"),
            "relevance_reason": f"OSV.dev match ({osv_id})",
            "cve_url": cve_url,
        }


osv_client = OsvClient()
