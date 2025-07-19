"""
CVE Service
Service that integrates the NIST NVD client with the local database
"""

import logging
from typing import List, Optional
from sqlalchemy.orm import Session

from app.services.nist_nvd import nist_client, CVEData
from app.database.models import CVE, Asset
from app.database.connection import get_db

logger = logging.getLogger(__name__)


class CVEService:
    """Service for CVE management"""

    def __init__(self):
        self.nist_client = nist_client

    def fetch_and_store_recent_cves(self, days: int = 7) -> int:
        """
        Retrieve and save recent CVEs from NIST NVD

        Args:
            days: Number of days back to search

        Returns:
            Number of CVEs saved
        """
        try:
            recent_cves = nist_client.get_recent_cves(days=days)

            stored_count = 0
            with next(get_db()) as db:
                for cve_data in recent_cves:
                    if self._store_cve(db, cve_data):
                        stored_count += 1

                db.commit()

            logger.info(
                f"Stored {stored_count} recent CVEs out of {len(recent_cves)} retrieved"
            )
            return stored_count

        except Exception as e:
            logger.error(f"Error retrieving recent CVEs: {e}")
            raise

    def search_cves_for_asset(
        self, asset_name: str, version: Optional[str] = None
    ) -> List[CVEData]:
        """
        Search CVEs for a specific asset

        Args:
            asset_name: Asset name
            version: Asset version (optional)

        Returns:
            List of CVEs that could affect the asset
        """
        try:
            return self.nist_client.search_cves_for_product(asset_name, version)
        except Exception as e:
            logger.error(f"Error in CVE search for asset {asset_name}: {e}")
            raise

    def check_assets_vulnerabilities(self, user_email: str) -> List[dict]:
        """
        Check vulnerabilities per tutti gli asset di un utente

        Args:
            user_email: Email of the user

        Returns:
            List of vulnerabilities found for the user's assets
        """
        vulnerabilities = []

        try:
            with next(get_db()) as db:
                user_assets = (
                    db.query(Asset).filter(Asset.user_email == user_email).all()
                )

                for asset in user_assets:
                    try:
                        asset_name = str(asset.name)  # type: ignore
                        asset_version = (
                            str(asset.version) if asset.version is not None else None
                        )  # type: ignore
                        asset_cves = self.search_cves_for_asset(
                            asset_name, asset_version
                        )

                        for cve_data in asset_cves:
                            vulnerability = {
                                "asset_id": asset.id,
                                "asset_name": asset.name,
                                "asset_version": asset.version,
                                "cve_id": cve_data.cve_id,
                                "severity": cve_data.severity,
                                "score": cve_data.score,
                                "summary": cve_data.summary,
                                "publish_date": cve_data.publish_date,
                            }
                            vulnerabilities.append(vulnerability)

                    except Exception as e:
                        logger.warning(
                            f"Error in vulnerability check per asset {asset.name}: {e}"
                        )
                        continue

        except Exception as e:
            logger.error(f"Error in vulnerability check per utente {user_email}: {e}")
            raise

        return vulnerabilities

    def _store_cve(self, db: Session, cve_data: CVEData) -> bool:
        """
        Save a CVE in the database (se non esiste già)

        Args:
            db: Sessione database
            cve_data: Dati del CVE da salvare

        Returns:
            True se il CVE è stato salvato, False se esisteva già
        """
        existing_cve = db.query(CVE).filter(CVE.id == cve_data.cve_id).first()

        if existing_cve:
            if (
                cve_data.modified_date
                and existing_cve.modified_date is not None  # type: ignore
                and cve_data.modified_date > existing_cve.modified_date
            ):  # type: ignore
                existing_cve.summary = cve_data.summary  # type: ignore
                existing_cve.severity = cve_data.severity  # type: ignore
                existing_cve.score = cve_data.score  # type: ignore
                existing_cve.modified_date = cve_data.modified_date  # type: ignore
                existing_cve.affected_products = cve_data.affected_products  # type: ignore

                logger.debug(f"Updated existing CVE: {cve_data.cve_id}")
                return True

            return False

        new_cve = CVE(
            id=cve_data.cve_id,
            summary=cve_data.summary,
            severity=cve_data.severity,
            score=cve_data.score,
            publish_date=cve_data.publish_date,
            modified_date=cve_data.modified_date,
            affected_products=cve_data.affected_products,
        )

        db.add(new_cve)
        logger.debug(f"Salvato nuovo CVE: {cve_data.cve_id}")
        return True

    def get_stored_cves(self, limit: int = 50) -> List[CVE]:
        """
        Retrieves CVEs stored in the database

        Args:
            limit: Maximum number of CVEs to return

        Returns:
            List of CVEs from the database
        """
        try:
            with next(get_db()) as db:
                cves = (
                    db.query(CVE).order_by(CVE.publish_date.desc()).limit(limit).all()
                )
                return cves
        except Exception as e:
            logger.error(f"Error in CVE retrieval dal database: {e}")
            raise


cve_service = CVEService()
