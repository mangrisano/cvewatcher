import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.database.models import Asset
from app.services.findings_repository import FindingRepository
from app.services.nist_nvd import nist_client, NvdUnavailableError
from app.services.enrichment import enrichment_service
from app.services.osv import osv_client
from app.services.sources import NvdSource, OsvSource, VulnerabilitySource
from app.services import matching
from app.services.severity import severity_rank
from app.models import AssetResponse

logger = logging.getLogger(__name__)


class CVEMonitoringService:
    def __init__(
        self, db: Session, sources: Optional[list[VulnerabilitySource]] = None
    ):
        self.db = db
        self.findings = FindingRepository(db)
        self.sources = (
            sources
            if sources is not None
            else [NvdSource(nist_client), OsvSource(osv_client)]
        )

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

            for asset in assets:
                logger.info(f"Monitoring asset: {asset.name} v{asset.version}")
                asset_result = await self._monitor_single_asset(asset)
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

    async def _monitor_single_asset(self, asset: Asset) -> dict[str, Any]:
        try:
            asset_response = AssetResponse.model_validate(asset)

            # Monitoring must never miss a freshly published CVE, so it bypasses
            # the read cache (the fetched result still refreshes it for readers).
            current_vulnerabilities = await self._get_asset_vulnerabilities(
                asset_response, use_cache=False
            )

            candidate_cve_ids = [
                vuln["cve_id"] for vuln in current_vulnerabilities if vuln.get("cve_id")
            ]
            existing_cve_ids = self.findings.linked_cve_ids(asset.id, candidate_cve_ids)

            new_vulnerabilities = []
            for vuln in current_vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id not in existing_cve_ids:
                    new_vulnerabilities.append(vuln)
                    self.findings.link(asset.id, vuln)

            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_version": asset.version,
                "user_email": asset.user_email,
                "total_vulnerabilities": len(current_vulnerabilities),
                "new_vulnerabilities": new_vulnerabilities,
                "existing_vulnerabilities": len(existing_cve_ids),
                "last_monitored": datetime.now(timezone.utc),
                "status": "success",
            }

        except Exception as e:
            logger.error(f"Error monitoring asset {asset.name}: {e}")
            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "error": str(e),
                "status": "error",
            }

    async def get_user_vulnerabilities(
        self,
        user_email: str,
        days: int = 0,
        severity_filter: str | None = None,
        use_cache: bool = True,
    ) -> list[dict[str, Any]]:
        """All vulnerabilities across a user's assets, via the precise engine.

        Uses the same CPE-aware, version-filtered, KEV/EPSS-enriched matching as
        the per-asset endpoint, tagging each finding with its originating asset.
        """
        assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()

        async def for_asset(asset: Asset) -> list[dict[str, Any]]:
            asset_response = AssetResponse.model_validate(asset)
            vulns = await self._get_asset_vulnerabilities(
                asset_response,
                days=days,
                severity_filter=severity_filter,
                use_cache=use_cache,
            )
            return [
                {
                    **vuln,
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "asset_version": asset.version,
                }
                for vuln in vulns
            ]

        # Assets are independent read-only lookups; run them concurrently. The
        # shared per-service semaphore keeps total NVD concurrency bounded.
        per_asset = await asyncio.gather(*(for_asset(asset) for asset in assets))
        return [vuln for asset_vulns in per_asset for vuln in asset_vulns]

    async def _get_asset_vulnerabilities(
        self,
        asset: AssetResponse,
        days: int = 0,
        severity_filter: str | None = None,
        use_cache: bool = True,
    ) -> list[dict[str, Any]]:
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

        if not vulnerabilities and any(result.unavailable for result in results):
            raise NvdUnavailableError(
                "Could not retrieve vulnerabilities: the NVD service is unavailable."
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

        await enrichment_service.enrich(vulnerabilities_list)

        # Actively-exploited (KEV) findings sort first, then by severity, then by
        # exploit probability (EPSS), then recency.
        vulnerabilities_list.sort(
            key=lambda x: (
                -int(bool(x.get("kev"))),
                -severity_rank(x.get("severity")),
                -(x.get("epss") or 0.0),
                -(
                    datetime.fromisoformat(
                        x.get("publish_date", "1900-01-01T00:00:00").replace(
                            "Z", "+00:00"
                        )
                    ).timestamp()
                    if x.get("publish_date")
                    else 0
                ),
                -(
                    datetime.fromisoformat(
                        x.get("modified_date", "1900-01-01T00:00:00").replace(
                            "Z", "+00:00"
                        )
                    ).timestamp()
                    if x.get("modified_date")
                    else 0
                ),
            )
        )

        self._attach_triage_status(asset, vulnerabilities_list)
        return vulnerabilities_list

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

        Uses the same engine as the findings endpoints (CPE-aware,
        version-filtered, all sources), one entry per CVE.
        """
        user_assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()
        if not user_assets:
            return {
                "message": "No assets registered for monitoring",
                "total_assets": 0,
            }

        findings = await self.get_user_vulnerabilities(user_email, days=days)
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
            "data_source": "NIST NVD + OSV.dev (live data)",
        }


def _timestamp(value: str | None) -> float:
    if not value:
        return 0
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
