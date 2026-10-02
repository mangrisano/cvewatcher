import asyncio
import logging
import weakref
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.database.models import Asset
from app.services.findings_query import FindingFilters, query_findings
from app.services.findings_repository import FindingRepository
from app.services.nist_nvd import NvdUnavailableError
from app.services.enrichment import EnrichmentService, enrichment_service
from app.services.sources import VulnerabilitySource, default_sources
from app.services import alerts, matching
from app.services.severity import severity_rank
from app.models import AssetResponse

logger = logging.getLogger(__name__)

# Assets scanned at once; each source also bounds its own requests.
_SCAN_CONCURRENCY = 8

# One scan per asset at a time: two overlapping scans would both report the
# same finding as new (duplicate alerts). Per process; the app runs one.
_asset_locks: "weakref.WeakValueDictionary[str, asyncio.Lock]" = (
    weakref.WeakValueDictionary()
)


def _asset_lock(asset_id: Any) -> asyncio.Lock:
    key = str(asset_id)
    lock = _asset_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _asset_locks[key] = lock
    return lock


class CVEMonitoringService:
    def __init__(
        self,
        db: Session,
        sources: Optional[list[VulnerabilitySource]] = None,
        enricher: Optional[EnrichmentService] = None,
    ):
        self.db = db
        self.findings = FindingRepository(db)
        self.sources = sources if sources is not None else default_sources()
        self.enricher = enricher if enricher is not None else enrichment_service

    async def monitor_all_assets(self) -> dict[str, Any]:
        try:
            assets = self.db.query(Asset).all()

            monitoring_results = {
                "timestamp": datetime.now(timezone.utc),
                "total_assets_monitored": len(assets),
                "asset_results": [],
                "summary": {
                    "new_vulnerabilities": 0,
                    "critical_vulnerabilities": 0,
                    "high_vulnerabilities": 0,
                    "medium_vulnerabilities": 0,
                    "low_vulnerabilities": 0,
                },
            }

            for asset_result in await self.monitor_assets(assets):
                monitoring_results["asset_results"].append(asset_result)

                monitoring_results["summary"]["new_vulnerabilities"] += len(
                    asset_result.get("new_vulnerabilities", [])
                )
                for vuln in asset_result.get("new_vulnerabilities", []):
                    severity = (vuln.get("severity") or "").upper()
                    if severity == "CRITICAL":
                        monitoring_results["summary"]["critical_vulnerabilities"] += 1
                    elif severity == "HIGH":
                        monitoring_results["summary"]["high_vulnerabilities"] += 1
                    elif severity == "MEDIUM":
                        monitoring_results["summary"]["medium_vulnerabilities"] += 1
                    elif severity == "LOW":
                        monitoring_results["summary"]["low_vulnerabilities"] += 1

            monitoring_results["asset_results"].sort(
                key=lambda asset_result: max(
                    [
                        vuln.get("publish_date", "1900-01-01T00:00:00")
                        for vuln in asset_result.get("new_vulnerabilities", [])
                    ],
                    default="1900-01-01T00:00:00",
                ),
                reverse=True,
            )

            return monitoring_results

        except Exception as e:
            logger.error(f"Error in monitor_all_assets: {e}")
            return {"error": str(e), "timestamp": datetime.now(timezone.utc)}

    async def monitor_asset(self, asset: Asset) -> dict[str, Any]:
        return (await self.monitor_assets([asset]))[0]

    async def monitor_assets(self, assets: list[Asset]) -> list[dict[str, Any]]:
        """Scan the assets and store what each scan found, one result per asset.

        Lookups run concurrently. Storing a scan has no awaits, so two stores
        never interleave on the shared session.
        """
        semaphore = asyncio.Semaphore(_SCAN_CONCURRENCY)

        async def scan(asset: Asset) -> dict[str, Any]:
            async with _asset_lock(asset.id):
                try:
                    async with semaphore:
                        # Monitoring must never miss a freshly published CVE,
                        # so it bypasses the read cache (and refreshes it).
                        found, complete = await self._collect(
                            AssetResponse.model_validate(asset), use_cache=False
                        )
                except Exception as e:
                    return self._scan_error(asset, e)
                return self._record_scan(asset, found, complete)

        return list(await asyncio.gather(*(scan(asset) for asset in assets)))

    def _scan_error(self, asset: Asset, error: Any) -> dict[str, Any]:
        logger.error(f"Error monitoring asset {asset.name}: {error}")
        return {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "error": str(error),
            "status": "error",
        }

    def _record_scan(
        self,
        asset: Asset,
        current_vulnerabilities: list[dict[str, Any]],
        complete: bool,
    ) -> dict[str, Any]:
        scanned_at = datetime.now(timezone.utc)
        candidate_cve_ids = [
            vuln["cve_id"] for vuln in current_vulnerabilities if vuln.get("cve_id")
        ]
        existing = self.findings.links(asset.id, candidate_cve_ids)
        kev_known = self.enricher.kev_catalog_loaded

        new_vulnerabilities = []
        escalations = []
        for vuln in current_vulnerabilities:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue
            link = existing.get(cve_id)
            if link is None:
                new_vulnerabilities.append(vuln)
            else:
                escalations.extend(alerts.observe(link, vuln, kev_known))
            self.findings.record(asset.id, vuln, kev_known, scanned_at, link)
        # A source that did not answer may have hidden findings: keep them all.
        if complete:
            self.findings.close_scan(asset, scanned_at)
        if not self.findings.save():
            # Nothing was stored: alerting now would repeat on the next scan.
            return self._scan_error(asset, "could not store the scan results")

        return {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "asset_version": asset.version,
            "user_email": asset.user_email,
            "total_vulnerabilities": len(current_vulnerabilities),
            "new_vulnerabilities": new_vulnerabilities,
            "escalations": escalations,
            "existing_vulnerabilities": len(existing),
            "last_monitored": scanned_at,
            "status": "success",
        }

    async def find_vulnerabilities(
        self,
        asset: AssetResponse,
        days: int = 0,
        severity_filter: str | None = None,
        use_cache: bool = True,
    ) -> list[dict[str, Any]]:
        """Findings for one asset from every source: merged, enriched, sorted."""
        findings, _ = await self._collect(asset, days, severity_filter, use_cache)
        return findings

    async def _collect(
        self,
        asset: AssetResponse,
        days: int = 0,
        severity_filter: str | None = None,
        use_cache: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Findings for one asset, and whether every source answered."""
        pub_start_date = None
        pub_end_date = None
        if days > 0:
            pub_end_date = datetime.now(timezone.utc)
            pub_start_date = pub_end_date - timedelta(days=days)

        results = await asyncio.gather(
            *(
                source.search(asset, pub_start_date, pub_end_date, use_cache)
                for source in self.sources
            )
        )
        vulnerabilities = [f for result in results for f in result.findings]
        complete = not any(result.unavailable for result in results)

        if not vulnerabilities and not complete:
            raise NvdUnavailableError(
                "Could not retrieve vulnerabilities: a vulnerability source "
                "(NVD or OSV.dev) is unavailable."
            )

        vulnerabilities_list = list(
            {
                vuln.get("cve_id"): vuln
                for vuln in sorted(vulnerabilities, key=matching.finding_richness)
                if vuln.get("cve_id")
            }.values()
        )

        if severity_filter:
            severity_filter_upper = severity_filter.upper()
            vulnerabilities_list = [
                vuln
                for vuln in vulnerabilities_list
                if (vuln.get("severity") or "").upper() == severity_filter_upper
            ]

        await self.enricher.enrich(vulnerabilities_list)

        # Actively-exploited (KEV) findings sort first, then by severity, then by
        # exploit probability (EPSS), then recency.
        vulnerabilities_list.sort(
            key=lambda x: (
                -int(bool(x.get("kev"))),
                -severity_rank(x.get("severity")),
                -(x.get("epss") or 0.0),
                -_timestamp(x.get("publish_date")),
                -_timestamp(x.get("modified_date")),
            )
        )

        self._attach_triage_status(asset, vulnerabilities_list)
        return vulnerabilities_list, complete

    def _attach_triage_status(
        self, asset: AssetResponse, findings: list[dict[str, Any]]
    ) -> None:
        """Tag each finding with its triage status from ``asset_cves`` (or 'open')."""
        cve_ids = [f["cve_id"] for f in findings if f.get("cve_id")]
        status_map = (
            self.findings.statuses(asset.id, cve_ids) if self.db is not None else {}
        )
        for finding in findings:
            cve_id = finding.get("cve_id")
            finding["status"] = status_map.get(cve_id, "open") if cve_id else "open"

    async def get_monitoring_report(
        self, user_email: str, days: int = 7
    ) -> dict[str, Any]:
        """CVEs published in the last ``days`` affecting the user's assets.

        Read from the findings stored by the last scans, one entry per CVE.
        """
        user_assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()
        if not user_assets:
            return {
                "message": "No assets registered for monitoring",
                "total_assets": 0,
            }

        findings = query_findings(
            self.db, user_email, FindingFilters(days=days, include_suppressed=True)
        ).findings
        recent: dict[str, dict[str, Any]] = {}
        for finding in findings:
            recent.setdefault(finding["cve_id"], finding)
        recent_cves = sorted(
            recent.values(),
            key=lambda x: (
                -severity_rank(x.get("severity")),
                -_timestamp(x.get("publish_date")),
            ),
        )
        by_severity = Counter(
            (cve.get("severity") or "").upper() for cve in recent_cves
        )

        return {
            "user_email": user_email,
            "report_period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_assets": len(user_assets),
            "assets": [
                {
                    "id": asset.id,
                    "name": asset.name,
                    "version": asset.version,
                    "description": asset.description,
                }
                for asset in user_assets
            ],
            "recent_vulnerabilities": recent_cves[:50],
            "vulnerability_summary": {
                "total_recent": len(recent_cves),
                "critical": by_severity["CRITICAL"],
                "high": by_severity["HIGH"],
                "medium": by_severity["MEDIUM"],
                "low": by_severity["LOW"],
            },
            "data_source": "NIST NVD + OSV.dev (as of the last scan)",
        }


def _timestamp(value: str | None) -> float:
    if not value:
        return 0
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
