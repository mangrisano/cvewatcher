import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy.orm import Session

from app.database.models import Asset, CVE
from app.services.nist_nvd import nist_client
from app.models import AssetResponse

logger = logging.getLogger(__name__)


class CVEMonitoringService:
    def __init__(self, db: Session):
        self.db = db
        self.nist_client = nist_client

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
                    severity = vuln.get("severity", "").upper()
                    if severity == "CRITICAL":
                        monitoring_results["summary"]["critical_vulnerabilities"] += 1
                    elif severity == "HIGH":
                        monitoring_results["summary"]["high_vulnerabilities"] += 1
                    elif severity == "MEDIUM":
                        monitoring_results["summary"]["medium_vulnerabilities"] += 1
                    elif severity == "LOW":
                        monitoring_results["summary"]["low_vulnerabilities"] += 1

            monitoring_results["asset_results"].sort(
                key=lambda asset_result: (
                    max(
                        [
                            vuln.get("publish_date", "1900-01-01T00:00:00")
                            for vuln in asset_result.get("new_vulnerabilities", [])
                        ],
                        default="1900-01-01T00:00:00",
                    )
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

            current_vulnerabilities = await self._get_asset_vulnerabilities(
                asset_response
            )

            existing_cves = self._get_existing_cves_for_asset(asset)
            existing_cve_ids = {cve.id for cve in existing_cves}

            new_vulnerabilities = []
            for vuln in current_vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id not in existing_cve_ids:
                    new_vulnerabilities.append(vuln)

                    await self._store_cve_for_asset(vuln, asset)

            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_version": asset.version,
                "user_email": asset.user_email,
                "total_vulnerabilities": len(current_vulnerabilities),
                "new_vulnerabilities": new_vulnerabilities,
                "existing_vulnerabilities": len(existing_cves),
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

    async def _get_asset_vulnerabilities(
        self, asset: AssetResponse, days: int = 0, severity_filter: str | None = None
    ) -> list[dict[str, Any]]:
        vulnerabilities = []
        search_queries = self._build_search_queries(asset)

        # Set up date filtering if days > 0
        pub_start_date = None
        pub_end_date = None
        if days > 0:
            pub_end_date = datetime.now(timezone.utc)
            pub_start_date = pub_end_date - timedelta(days=days)

        for query in search_queries[:3]:
            try:
                # Use date range filtering at the API level for better results
                cves = self.nist_client.search_cves(
                    keyword=query,
                    results_per_page=100,
                    pub_start_date=pub_start_date,
                    pub_end_date=pub_end_date,
                )

                for cve in cves:
                    if self._is_relevant_to_asset(cve, asset):
                        vulnerabilities.append(
                            {
                                "cve_id": cve.cve_id,
                                "summary": cve.summary,
                                "severity": cve.severity,
                                "score": cve.score,
                                "publish_date": cve.publish_date.isoformat()
                                if cve.publish_date
                                else None,
                                "modified_date": cve.modified_date.isoformat()
                                if cve.modified_date
                                else None,
                                "relevance_reason": f"Matches asset name '{asset.name}'",
                                "cve_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve_id}",
                            }
                        )
            except Exception as e:
                logger.error(f"Error searching for {query}: {e}")
                continue

        unique_cves = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if cve_id not in unique_cves:
                unique_cves[cve_id] = vuln

        vulnerabilities_list = list(unique_cves.values())

        # Apply severity filter if specified
        if severity_filter:
            severity_filter_upper = severity_filter.upper()
            vulnerabilities_list = [
                vuln
                for vuln in vulnerabilities_list
                if vuln.get("severity", "").upper() == severity_filter_upper
            ]

        vulnerabilities_list.sort(
            key=lambda x: (
                -self._get_severity_priority(x.get("severity")),
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

        return vulnerabilities_list

    def _get_severity_priority(self, severity: str) -> int:
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return severity_map.get(severity or "LOW", 1)

    def _build_search_queries(self, asset: AssetResponse) -> list[str]:
        queries = []

        if asset.name:
            queries.append(asset.name)
            name_lower = asset.name.lower()
            queries.append(name_lower.replace(" ", ""))
            queries.append(name_lower.replace(" ", "-"))

        if asset.cpe:
            queries.append(asset.cpe)

        if asset.version and asset.name:
            queries.append(f"{asset.name} {asset.version}")

        return list(set(queries))

    def _is_relevant_to_asset(self, cve_data, asset: AssetResponse) -> bool:
        summary_lower = cve_data.summary.lower()

        if asset.name:
            asset_name_lower = asset.name.lower()
            # Check if asset name is in summary
            if asset_name_lower in summary_lower:
                return True
            # Check if asset name (without spaces or with hyphens) is in summary
            if asset_name_lower.replace(" ", "") in summary_lower:
                return True
            if asset_name_lower.replace(" ", "-") in summary_lower:
                return True

        if asset.version and asset.version.lower() in summary_lower:
            return True

        # Check affected products if available
        if hasattr(cve_data, "affected_products") and cve_data.affected_products:
            affected_products_str = str(cve_data.affected_products).lower()
            if asset.name and asset.name.lower() in affected_products_str:
                return True

        return False

    def _get_existing_cves_for_asset(self, asset: Asset) -> list[CVE]:
        return self.db.query(CVE).all()

    async def _store_cve_for_asset(self, vuln_data: dict[str, Any], asset: Asset):
        try:
            existing_cve = (
                self.db.query(CVE).filter(CVE.id == vuln_data.get("cve_id")).first()
            )

            if not existing_cve:
                publish_date = None
                if vuln_data.get("publish_date"):
                    try:
                        publish_date = datetime.fromisoformat(
                            vuln_data.get("publish_date", "").replace("Z", "+00:00")
                        )
                    except Exception:
                        pass

                new_cve = CVE(
                    id=vuln_data.get("cve_id"),
                    summary=vuln_data.get("summary", ""),
                    severity=vuln_data.get("severity"),
                    score=vuln_data.get("score"),
                    publish_date=publish_date,
                    affected_products=[
                        {
                            "asset_name": asset.name,
                            "asset_version": asset.version,
                            "user_email": asset.user_email,
                        }
                    ],
                )

                self.db.add(new_cve)
                self.db.commit()
                logger.info(
                    f"Stored new CVE: {vuln_data.get('cve_id')} for asset {asset.name}"
                )

        except Exception as e:
            logger.error(f"Error storing CVE {vuln_data.get('cve_id')}: {e}")
            self.db.rollback()

    async def get_monitoring_report(
        self, user_email: str, days: int = 7
    ) -> dict[str, Any]:
        try:
            user_assets = (
                self.db.query(Asset).filter(Asset.user_email == user_email).all()
            )

            if not user_assets:
                return {
                    "message": "No assets registered for monitoring",
                    "total_assets": 0,
                }

            logger.info(
                f"Generating monitoring report for {len(user_assets)} assets over {days} days"
            )

            all_relevant_cves = []

            for asset in user_assets:
                logger.info(f"Searching for CVEs related to asset: {asset.name}")

                asset_response = AssetResponse.model_validate(asset)
                search_queries = self._build_search_queries(asset_response)

                try:
                    logger.info(
                        f"Searching for CVEs related to {asset.name} in last {days} days"
                    )

                    # Search for each query term separately to ensure we don't miss anything
                    for query in search_queries:
                        logger.info(f"Searching with keyword: {query}")
                        query_cves = self.nist_client.search_cves(
                            keyword=query,
                            pub_start_date=datetime.now(timezone.utc)
                            - timedelta(days=days),
                            pub_end_date=datetime.now(timezone.utc),
                            results_per_page=100,
                        )
                        logger.info(
                            f"Found {len(query_cves)} CVEs for keyword '{query}'"
                        )

                        for cve_data in query_cves:
                            cve_dict = {
                                "cve_id": cve_data.cve_id,
                                "summary": cve_data.summary,
                                "severity": cve_data.severity,
                                "score": cve_data.score,
                                "publish_date": cve_data.publish_date.isoformat()
                                if cve_data.publish_date
                                else None,
                                "asset_name": asset.name,
                                "matched_query": query,
                                "cve_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_data.cve_id}",
                            }

                            # Avoid duplicates
                            if not any(
                                existing.get("cve_id") == cve_dict.get("cve_id")
                                for existing in all_relevant_cves
                            ):
                                all_relevant_cves.append(cve_dict)
                                logger.info(
                                    f"Found relevant CVE: {cve_dict.get('cve_id')} (matched: {query})"
                                )

                except Exception as e:
                    logger.error(f"Error fetching CVEs for asset {asset.name}: {e}")
                    continue

            logger.info(f"Found {len(all_relevant_cves)} relevant CVEs")

            all_relevant_cves.sort(
                key=lambda x: (
                    -self._get_severity_priority(x.get("severity")),
                    -(
                        datetime.fromisoformat(
                            x.get("publish_date", "1900-01-01T00:00:00").replace(
                                "Z", "+00:00"
                            )
                        ).timestamp()
                        if x.get("publish_date")
                        else 0
                    ),
                )
            )
            logger.info(
                "Sorted CVEs by severity (highest first), then by publish date (most recent first)"
            )

            report = {
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
                "recent_vulnerabilities": all_relevant_cves[:50],
                "vulnerability_summary": {
                    "total_recent": len(all_relevant_cves),
                    "critical": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "CRITICAL"
                    ),
                    "high": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "HIGH"
                    ),
                    "medium": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "MEDIUM"
                    ),
                    "low": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "LOW"
                    ),
                },
                "data_source": "NIST NVD API (live data)",
            }

            return report

        except Exception as e:
            logger.error(f"Error generating monitoring report: {e}")
            return {"error": str(e)}

    async def scan_for_new_cves_since(self, since_date: datetime) -> dict[str, Any]:
        try:
            assets = self.db.query(Asset).all()
            new_findings = []

            for asset in assets:
                asset_response = AssetResponse.model_validate(asset)
                search_queries = self._build_search_queries(asset_response)

                for query in search_queries[:2]:
                    try:
                        cves = self.nist_client.search_cves(
                            keyword=query,
                            pub_start_date=since_date,
                            results_per_page=50,
                        )

                        for cve in cves:
                            if self._is_relevant_to_asset(cve, asset_response):
                                new_findings.append(
                                    {
                                        "asset_id": asset.id,
                                        "asset_name": asset.name,
                                        "asset_version": asset.version,
                                        "user_email": asset.user_email,
                                        "cve_id": cve.cve_id,
                                        "summary": cve.summary,
                                        "severity": cve.severity,
                                        "score": cve.score,
                                        "publish_date": cve.publish_date.isoformat()
                                        if cve.publish_date
                                        else None,
                                        "cve_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve_id}",
                                    }
                                )
                    except Exception as e:
                        logger.error(f"Error scanning {query}: {e}")
                        continue

            new_findings.sort(
                key=lambda x: x.get("publish_date") or "1900-01-01T00:00:00",
                reverse=True,
            )

            return {
                "scan_date": datetime.now(timezone.utc),
                "since_date": since_date,
                "total_new_findings": len(new_findings),
                "findings": new_findings,
            }

        except Exception as e:
            logger.error(f"Error scanning for new CVEs: {e}")
            return {"error": str(e)}
