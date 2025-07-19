import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.models import Asset, CVE
from app.services.nist_nvd import nist_client
from app.models import AssetResponse

logger = logging.getLogger(__name__)


class CVEMonitoringService:
    def __init__(self, db: Session):
        self.db = db
        self.nist_client = nist_client

    async def monitor_all_assets(self) -> Dict[str, Any]:
        try:
            assets = self.db.query(Asset).all()

            monitoring_results = {
                "timestamp": datetime.utcnow(),
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
                    asset_result["new_vulnerabilities"]
                )
                for vuln in asset_result["new_vulnerabilities"]:
                    severity = vuln.get("severity", "").upper()
                    if severity == "CRITICAL":
                        monitoring_results["summary"]["critical_vulnerabilities"] += 1
                    elif severity == "HIGH":
                        monitoring_results["summary"]["high_vulnerabilities"] += 1
                    elif severity == "MEDIUM":
                        monitoring_results["summary"]["medium_vulnerabilities"] += 1
                    elif severity == "LOW":
                        monitoring_results["summary"]["low_vulnerabilities"] += 1

            return monitoring_results

        except Exception as e:
            logger.error(f"Error in monitor_all_assets: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow()}

    async def _monitor_single_asset(self, asset: Asset) -> Dict[str, Any]:
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
                "last_monitored": datetime.utcnow(),
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
        self, asset: AssetResponse
    ) -> List[Dict[str, Any]]:
        vulnerabilities = []
        search_queries = self._build_search_queries(asset)

        for query in search_queries[:3]:
            try:
                cves = self.nist_client.search_cves(keyword=query, results_per_page=100)

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
                            }
                        )
            except Exception as e:
                logger.error(f"Error searching for {query}: {e}")
                continue

        unique_cves = {}
        for vuln in vulnerabilities:
            cve_id = vuln["cve_id"]
            if cve_id not in unique_cves:
                unique_cves[cve_id] = vuln

        vulnerabilities_list = list(unique_cves.values())
        vulnerabilities_list.sort(
            key=lambda x: (
                x.get("publish_date") or "1900-01-01T00:00:00",
                x.get("modified_date") or "1900-01-01T00:00:00",
            ),
            reverse=True,
        )

        return vulnerabilities_list

    def _build_search_queries(self, asset: AssetResponse) -> List[str]:
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
        if asset.name and asset.name.lower() in cve_data.summary.lower():
            return True
        if asset.version and asset.version.lower() in cve_data.summary.lower():
            return True
        return False

    def _get_existing_cves_for_asset(self, asset: Asset) -> List[CVE]:
        return self.db.query(CVE).all()

    async def _store_cve_for_asset(self, vuln_data: Dict[str, Any], asset: Asset):
        try:
            existing_cve = (
                self.db.query(CVE).filter(CVE.id == vuln_data["cve_id"]).first()
            )

            if not existing_cve:
                publish_date = None
                if vuln_data.get("publish_date"):
                    try:
                        publish_date = datetime.fromisoformat(
                            vuln_data["publish_date"].replace("Z", "+00:00")
                        )
                    except Exception:
                        pass

                new_cve = CVE(
                    id=vuln_data["cve_id"],
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
                    f"Stored new CVE: {vuln_data['cve_id']} for asset {asset.name}"
                )

        except Exception as e:
            logger.error(f"Error storing CVE {vuln_data.get('cve_id')}: {e}")
            self.db.rollback()

    async def get_monitoring_report(
        self, user_email: str, days: int = 7
    ) -> Dict[str, Any]:
        try:
            user_assets = (
                self.db.query(Asset).filter(Asset.user_email == user_email).all()
            )

            if not user_assets:
                return {
                    "message": "No assets registered for monitoring",
                    "total_assets": 0,
                }

            since_date = datetime.utcnow() - timedelta(days=days)

            user_relevant_cves = []
            asset_names = {asset.name.lower() for asset in user_assets}

            recent_cves = (
                self.db.query(CVE)
                .filter(CVE.publish_date >= since_date)
                .order_by(desc(CVE.publish_date))
                .all()
            )

            for cve in recent_cves:
                cve_summary_lower = cve.summary.lower()

                for asset_name in asset_names:
                    if asset_name in cve_summary_lower:
                        user_relevant_cves.append(cve)
                        break

            report = {
                "user_email": user_email,
                "report_period_days": days,
                "generated_at": datetime.utcnow(),
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
                "recent_vulnerabilities": [
                    {
                        "cve_id": cve.id,
                        "summary": cve.summary,
                        "severity": cve.severity,
                        "score": cve.score,
                        "publish_date": str(cve.publish_date),
                    }
                    for cve in user_relevant_cves[:20]
                ],
                "vulnerability_summary": {
                    "total_recent": len(user_relevant_cves),
                    "critical": sum(
                        1
                        for cve in user_relevant_cves
                        if str(cve.severity) == "CRITICAL"
                    ),
                    "high": sum(
                        1 for cve in user_relevant_cves if str(cve.severity) == "HIGH"
                    ),
                    "medium": sum(
                        1 for cve in user_relevant_cves if str(cve.severity) == "MEDIUM"
                    ),
                    "low": sum(
                        1 for cve in user_relevant_cves if str(cve.severity) == "LOW"
                    ),
                },
            }

            return report

        except Exception as e:
            logger.error(f"Error generating monitoring report: {e}")
            return {"error": str(e)}

    async def scan_for_new_cves_since(self, since_date: datetime) -> Dict[str, Any]:
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
                "scan_date": datetime.utcnow(),
                "since_date": since_date,
                "total_new_findings": len(new_findings),
                "findings": new_findings,
            }

        except Exception as e:
            logger.error(f"Error scanning for new CVEs: {e}")
            return {"error": str(e)}
