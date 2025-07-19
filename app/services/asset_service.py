from typing import List, Optional, Dict, Any
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
        self, user_email: str, asset_data: AssetCreate
    ) -> AssetResponse:
        """Create a new asset for monitoring."""

        # Check if asset already exists for this user
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

        # Create new asset
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

    async def get_user_assets(self, user_email: str) -> List[AssetResponse]:
        """Get all assets for a specific user."""
        assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()
        return [AssetResponse.model_validate(asset) for asset in assets]

    async def get_asset_by_id(
        self, asset_id: int, user_email: str
    ) -> Optional[AssetResponse]:
        """Get a specific asset by ID, ensuring it belongs to the user."""
        asset = (
            self.db.query(Asset)
            .filter(and_(Asset.id == asset_id, Asset.user_email == user_email))
            .first()
        )

        if asset:
            return AssetResponse.model_validate(asset)
        return None

    async def delete_asset(self, asset_id: int, user_email: str) -> bool:
        """Delete an asset."""
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
    ) -> List[Dict[str, Any]]:
        """Get all CVEs affecting a specific asset."""
        vulnerabilities = []

        # Search strategies
        search_queries = self._build_search_queries(asset)

        for query in search_queries:
            try:
                # Search NIST NVD - returns List[CVEData]
                cves = self.nist_client.search_cves(keyword=query, results_per_page=100)

                if cves:
                    for cve_data in cves:
                        if self._is_relevant_to_cve_data(cve_data, asset):
                            # Convert CVEData to dict format for consistency
                            vuln_dict = {
                                "cve": {
                                    "id": cve_data.cve_id,
                                    "summary": cve_data.summary,
                                    "severity": cve_data.severity,
                                    "score": cve_data.score,
                                    "published_date": cve_data.publish_date,
                                    "modified_date": cve_data.modified_date,
                                }
                            }
                            vulnerabilities.append(vuln_dict)

            except Exception as e:
                print(f"Error searching for {query}: {e}")
                continue

        # Remove duplicates
        unique_cves = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve", {}).get("id")
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = vuln

        return list(unique_cves.values())

    async def scan_asset_for_cves(self, asset: AssetResponse) -> Dict[str, Any]:
        """Perform a comprehensive CVE scan for an asset."""
        scan_timestamp = datetime.utcnow()

        # Get existing CVE count for this asset
        existing_cves = await self.get_asset_vulnerabilities(asset)
        existing_count = len(existing_cves)

        # Perform new scan
        new_vulnerabilities = await self.get_asset_vulnerabilities(asset)

        # Calculate new findings
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

    def _build_search_queries(self, asset: AssetResponse) -> List[str]:
        """Build search queries for finding CVEs related to an asset."""
        queries = []

        # Primary search by name
        if asset.name:
            queries.append(asset.name)

            # Add common variations
            name_lower = asset.name.lower()
            queries.append(name_lower.replace(" ", ""))  # Remove spaces
            queries.append(name_lower.replace(" ", "-"))  # Replace spaces with hyphens
            queries.append(
                name_lower.replace(" ", "_")
            )  # Replace spaces with underscores

        # Search by CPE if available
        if asset.cpe:
            queries.append(asset.cpe)

            # Extract vendor and product from CPE
            cpe_parts = self._parse_cpe(asset.cpe)
            if cpe_parts:
                if cpe_parts.get("vendor"):
                    queries.append(cpe_parts["vendor"])
                if cpe_parts.get("product"):
                    queries.append(cpe_parts["product"])
                if cpe_parts.get("vendor") and cpe_parts.get("product"):
                    queries.append(f"{cpe_parts['vendor']} {cpe_parts['product']}")

        # Add version-specific searches
        if asset.version:
            if asset.name:
                queries.append(f"{asset.name} {asset.version}")

        return list(set(queries))  # Remove duplicates

    def _parse_cpe(self, cpe: str) -> Optional[Dict[str, Optional[str]]]:
        """Parse CPE string to extract vendor, product, version."""
        try:
            # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
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
        """Check if a CVEData object is relevant to the asset."""
        # Check if asset name appears in the CVE summary
        if asset.name and asset.name.lower() in cve_data.summary.lower():
            return True

        # Check version matching in summary
        if asset.version and asset.version.lower() in cve_data.summary.lower():
            return True

        # For now, be inclusive - we can add more sophisticated matching later
        return True

    def _is_relevant_to_asset(
        self, vuln_data: Dict[str, Any], asset: AssetResponse
    ) -> bool:
        """Check if a CVE is relevant to the asset."""
        cve_item = vuln_data.get("cve", {})

        # Check descriptions for asset name mentions
        descriptions = cve_item.get("descriptions", [])
        for desc in descriptions:
            desc_text = desc.get("value", "").lower()
            if asset.name.lower() in desc_text:
                return True

        # Check CPE matches in configurations
        if asset.cpe:
            configurations = cve_item.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match = node.get("cpeMatch", [])
                    for match in cpe_match:
                        if asset.cpe.lower() in match.get("criteria", "").lower():
                            return True

        # Check version matching
        if asset.version:
            # This is a simplified check - in production you'd want more sophisticated version comparison
            vuln_text = str(vuln_data).lower()
            if asset.version.lower() in vuln_text:
                return True

        return True  # For now, be inclusive rather than exclusive
