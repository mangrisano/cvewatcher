"""OSV.dev client: vulnerabilities for a package in a given ecosystem.

NVD/CPE matching is weak for language-package dependencies (npm, PyPI, Go, …)
and for distribution packages (Debian, Ubuntu, Alpine, …); OSV.dev covers both.
A failed query raises :class:`OsvError`, so it is never mistaken for "no
vulnerabilities".
"""

import logging
from typing import Any, Optional

import httpx
from cvss import CVSS2, CVSS3, CVSS4

from app.services.severity import KNOWN_SEVERITIES, band_from_score

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
# Distro packages such as Debian's "linux" span several pages of results.
MAX_PAGES = 10

# https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
OSV_ECOSYSTEMS = (
    "AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux",
    "BellSoft Hardened Containers", "Bitnami", "CRAN", "Chainguard",
    "CleanStart", "Debian", "Echo", "GHC", "GIT", "GitHub Actions", "Go",
    "Hackage", "Hex", "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet",
    "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Red Hat", "Rocky Linux", "Root",
    "RubyGems", "SUSE", "SwiftURL", "TuxCare", "Ubuntu", "VSCode", "Wolfi",
    "crates.io", "npm", "opam", "openEuler", "openSUSE",
)  # fmt: skip
_CANONICAL_ECOSYSTEMS = {name.lower(): name for name in OSV_ECOSYSTEMS}


class OsvError(Exception):
    """OSV.dev did not answer the query."""


def normalize_ecosystem(value: str) -> str:
    """Canonical OSV spelling of ``value`` ("debian:13" -> "Debian:13").

    Only the ecosystem name is checked; a release suffix such as ":13" or
    ":24.04:LTS" is kept as written. Raises ValueError for an unknown name.
    """
    base, sep, release = value.strip().partition(":")
    canonical = _CANONICAL_ECOSYSTEMS.get(base.strip().lower())
    if canonical is None:
        raise ValueError(
            f"Unknown ecosystem '{base.strip()}'. Use an OSV.dev ecosystem such as "
            "PyPI, npm, Debian:13, Ubuntu:24.04:LTS or Alpine:v3.22."
        )
    return canonical + sep + release.strip()


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
    # A 0.0 base score means "no impact": no band, unlike an NVD 0.0.
    return band_from_score(score) if score else None


async def _http_post(url: str, **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.post(url, **kwargs)


class OsvClient:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    async def search(
        self, ecosystem: str, name: str, version: Optional[str] = None
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version
        vulns: list[dict[str, Any]] = []
        try:
            for _ in range(MAX_PAGES):
                response = await _http_post(
                    OSV_QUERY_URL, json=body, timeout=self.timeout
                )
                response.raise_for_status()
                payload = response.json()
                vulns.extend(payload.get("vulns", []))
                token = payload.get("next_page_token")
                if not token:
                    break
                body["page_token"] = token
            else:
                logger.warning(
                    "OSV results truncated at %d pages for %s/%s",
                    MAX_PAGES,
                    ecosystem,
                    name,
                )
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("OSV query failed for %s/%s: %s", ecosystem, name, e)
            raise OsvError(f"OSV.dev query failed for {ecosystem}/{name}") from e
        return [finding for vuln in vulns for finding in self._to_findings(vuln)]

    @staticmethod
    def _to_findings(vuln: dict[str, Any]) -> list[dict[str, Any]]:
        """One finding per CVE the record covers, else one under its OSV id.

        Distro records name their CVEs under "upstream" (DEBIAN-CVE-… one,
        a Red Hat RHSA often several); language advisories under "aliases".
        """
        osv_id = vuln.get("id", "")
        related = [*(vuln.get("aliases") or []), *(vuln.get("upstream") or [])]
        cve_ids = list(dict.fromkeys(a for a in related if a.startswith("CVE-")))

        # Score from the CVSS vector; band from the explicit GHSA severity when
        # present, otherwise derived from the computed score.
        vector = _best_cvss_vector(vuln.get("severity"))
        score = _cvss_base_score(vector) if vector else None
        raw_severity = str((vuln.get("database_specific") or {}).get("severity") or "")
        severity = _SEVERITY_MAP.get(raw_severity.upper(), raw_severity.upper())
        if severity not in KNOWN_SEVERITIES:
            # Third-party text: never store a value outside the known bands.
            severity = _band_from_score(score)

        summary = vuln.get("summary") or (vuln.get("details") or "")[:300]
        return [
            {
                "cve_id": cve_id,
                "summary": summary,
                "severity": severity,
                "score": score,
                "publish_date": vuln.get("published"),
                "modified_date": vuln.get("modified"),
                "relevance_reason": f"OSV.dev match ({osv_id})",
                "cve_url": f"https://www.cve.org/CVERecord?id={cve_id}"
                if cve_id.startswith("CVE-")
                else f"https://osv.dev/vulnerability/{osv_id}",
            }
            for cve_id in cve_ids or [osv_id]
        ]


osv_client = OsvClient()
