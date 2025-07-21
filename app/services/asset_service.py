import logging
from typing import Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime
from app.database.models import Asset
from app.models import AssetCreate, AssetResponse
from app.services.nist_nvd import nist_client
from app.services.cve_service import CVEService


class AssetService:
    def __init__(self, db: Session):
        self.db = db
        self.nist_client = nist_client
        self.cve_service = CVEService()

    async def create_asset(
        self, asset_data: AssetCreate, user_email: str
    ) -> AssetResponse:
        existing = (
            self.db.query(Asset)
            .filter(
                and_(
                    Asset.name == asset_data.name,
                    Asset.user_email == user_email,
                    Asset.version == asset_data.version,
                )
            )
            .first()
        )

        if existing:
            raise ValueError(
                f"Asset '{asset_data.name}' version '{asset_data.version}' already exists"
            )

        db_asset = Asset(
            name=asset_data.name,
            version=asset_data.version,
            cpe=asset_data.cpe,
            user_email=user_email,
            description=asset_data.description,
        )

        self.db.add(db_asset)
        self.db.commit()
        self.db.refresh(db_asset)

        return AssetResponse.model_validate(db_asset)

    async def get_user_assets(self, user_email: str) -> list[AssetResponse]:
        assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()
        return [AssetResponse.model_validate(asset) for asset in assets]

    async def get_asset_by_id(
        self, asset_id: int, user_email: str
    ) -> Optional[AssetResponse]:
        asset = (
            self.db.query(Asset)
            .filter(and_(Asset.id == asset_id, Asset.user_email == user_email))
            .first()
        )

        if asset:
            return AssetResponse.model_validate(asset)
        return None

    async def delete_asset(self, asset_id: int, user_email: str) -> bool:
        asset = (
            self.db.query(Asset)
            .filter(and_(Asset.id == asset_id, Asset.user_email == user_email))
            .first()
        )

        if asset:
            self.db.delete(asset)
            self.db.commit()
            return True
        return False

    async def get_asset_vulnerabilities(
        self, asset: AssetResponse
    ) -> list[dict[str, Any]]:
        vulnerabilities = []

        search_queries = self._build_search_queries(asset)

        for query in search_queries:
            try:
                cves = self.nist_client.search_cves(keyword=query, results_per_page=100)

                if cves:
                    vulnerabilities.extend(
                        [
                            {
                                "cve": {
                                    "id": cve.cve_id,
                                    "summary": cve.summary,
                                    "severity": cve.severity,
                                    "score": cve.score,
                                    "published_date": cve.publish_date,
                                    "modified_date": cve.modified_date,
                                }
                            }
                            for cve in cves
                            if self._is_relevant_to_cve_data(cve, asset)
                        ]
                    )

            except Exception as e:
                logging.warning(f"Error searching for {query}: {e}")
                continue

        seen_ids = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve", {}).get("id")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique_vulns.append(vuln)
        return unique_vulns

    async def scan_asset_for_cves(self, asset: AssetResponse) -> dict[str, Any]:
        from datetime import timezone

        scan_timestamp = datetime.now(timezone.utc)

        existing_cves = await self.get_asset_vulnerabilities(asset)
        existing_count = len(existing_cves)

        new_vulnerabilities = await self.get_asset_vulnerabilities(asset)

        new_count = (
            len(new_vulnerabilities) - existing_count
            if len(new_vulnerabilities) > existing_count
            else 0
        )

        return {
            "timestamp": scan_timestamp,
            "asset_id": asset.id,
            "new_count": new_count,
            "total_count": len(new_vulnerabilities),
            "vulnerabilities": new_vulnerabilities,
        }

    def _build_search_queries(self, asset: AssetResponse) -> list[str]:
        queries = []

        if asset.name:
            queries.append(asset.name)

            name_lower = asset.name.lower()
            queries.append(name_lower.replace(" ", ""))
            queries.append(name_lower.replace(" ", "-"))
            queries.append(name_lower.replace(" ", "_"))

        if asset.cpe:
            queries.append(asset.cpe)

            cpe_parts = self._parse_cpe(asset.cpe)
            if cpe_parts:
                if cpe_parts.get("vendor"):
                    queries.append(cpe_parts["vendor"])
                if cpe_parts.get("product"):
                    queries.append(cpe_parts["product"])
                if cpe_parts.get("vendor") and cpe_parts.get("product"):
                    queries.append(f"{cpe_parts['vendor']} {cpe_parts['product']}")

        if asset.version:
            if asset.name:
                queries.append(f"{asset.name} {asset.version}")

        return list(set(queries))

    def _parse_cpe(self, cpe: str) -> Optional[dict[str, Optional[str]]]:
        try:
            parts = cpe.split(":")
            if len(parts) >= 5:
                return {
                    "vendor": parts[3] if parts[3] != "*" else None,
                    "product": parts[4] if parts[4] != "*" else None,
                    "version": parts[5] if len(parts) > 5 and parts[5] != "*" else None,
                }
        except Exception:
            pass
        return None

    def _is_relevant_to_cve_data(self, cve_data, asset: AssetResponse) -> bool:
        if asset.name and asset.name.lower() in cve_data.summary.lower():
            return True

        if asset.version and asset.version.lower() in cve_data.summary.lower():
            return True

        return True

    def _is_relevant_to_asset(
        self, vuln_data: dict[str, Any], asset: AssetResponse
    ) -> bool:
        cve_item = vuln_data.get("cve", {})

        descriptions = cve_item.get("descriptions", [])
        for desc in descriptions:
            desc_text = desc.get("value", "").lower()
            if asset.name.lower() in desc_text:
                return True

        if asset.cpe:
            configurations = cve_item.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match = node.get("cpeMatch", [])
                    for match in cpe_match:
                        if asset.cpe.lower() in match.get("criteria", "").lower():
                            return True

        if asset.version:
            vuln_text = str(vuln_data).lower()
            if asset.version.lower() in vuln_text:
                return True

        return True
