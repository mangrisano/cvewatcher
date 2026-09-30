"""Persistence of findings: the ``asset_cves`` links and the shared ``cves`` rows."""

import logging
from datetime import datetime
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import Column
from sqlalchemy.orm import Session

from app.database.models import CVE, AssetCVE
from app.models import FindingStatus
from app.services.severity import severity_band

logger = logging.getLogger(__name__)

# The 1.x-style models type ``Asset.id`` as a Column for static checkers.
AssetId = UUID | Column


class FindingRepository:
    def __init__(self, db: Session):
        self.db = db

    def statuses(self, asset_id: AssetId, cve_ids: Iterable[str]) -> dict[str, str]:
        """Triage status of the given CVEs on an asset (only those linked)."""
        cve_ids = list(cve_ids)
        if not cve_ids:
            return {}
        rows = (
            self.db.query(AssetCVE.cve_id, AssetCVE.status)
            .filter(AssetCVE.asset_id == asset_id, AssetCVE.cve_id.in_(cve_ids))
            .all()
        )
        return {cve_id: status for cve_id, status in rows}

    def links(
        self, asset_id: AssetId, candidates: Iterable[str]
    ) -> dict[str, AssetCVE]:
        """The asset's existing links among the given CVE ids, keyed by CVE id.

        Only the candidate ids are queried, so this never scans the whole table.
        """
        candidates = list(candidates)
        if not candidates:
            return {}
        rows = (
            self.db.query(AssetCVE)
            .filter(AssetCVE.asset_id == asset_id, AssetCVE.cve_id.in_(candidates))
            .all()
        )
        return {str(row.cve_id): row for row in rows}

    def link(
        self, asset_id: AssetId, finding: dict[str, Any], kev_known: bool = False
    ) -> None:
        """Persist a newly seen finding; best-effort (errors are logged).

        ``kev_known`` says whether the KEV catalog was available, so a missing
        catalog is not recorded as "not in KEV".
        """
        cve_id = finding.get("cve_id")
        if not cve_id:
            return
        try:
            if not self.db.query(CVE).filter(CVE.id == cve_id).first():
                # The shared CVE row holds only global metadata; the per-asset
                # link lives in ``asset_cves`` (no tenant data here).
                self.db.add(
                    CVE(
                        id=cve_id,
                        summary=finding.get("summary", ""),
                        severity=finding.get("severity"),
                        score=finding.get("score"),
                        publish_date=_parse_date(finding.get("publish_date")),
                    )
                )
            if not self._get_link(asset_id, cve_id):
                self.db.add(
                    AssetCVE(
                        asset_id=asset_id,
                        cve_id=cve_id,
                        kev=bool(finding.get("kev")) if kev_known else None,
                        severity=severity_band(finding.get("severity")),
                    )
                )
            self.db.commit()
            logger.info("Stored new CVE %s for asset %s", cve_id, asset_id)
        except Exception as e:
            logger.error("Error storing CVE %s: %s", cve_id, e)
            self.db.rollback()

    def save(self) -> None:
        """Commit changes made to loaded links; best-effort."""
        try:
            self.db.commit()
        except Exception as e:
            logger.error("Error saving finding state: %s", e)
            self.db.rollback()

    def set_status(
        self, asset_id: AssetId, cve_id: str, status: str, notes: str | None
    ) -> AssetCVE:
        """Create or update the triage status of an (asset, CVE) finding."""
        link = self._get_link(asset_id, cve_id)
        if link is None:
            # The finding may not have been persisted yet; ensure the shared CVE
            # row exists (FK) then create the link.
            if not self.db.query(CVE).filter(CVE.id == cve_id).first():
                self.db.add(CVE(id=cve_id))
            link = AssetCVE(asset_id=asset_id, cve_id=cve_id)
            self.db.add(link)
        link.status = status  # type: ignore[assignment]
        link.notes = notes  # type: ignore[assignment]
        self.db.commit()
        self.db.refresh(link)
        return link

    def drop_untriaged(self, asset_id: AssetId) -> None:
        """Remove the asset's ``open`` links, within the caller's transaction."""
        self.db.query(AssetCVE).filter(
            AssetCVE.asset_id == asset_id,
            AssetCVE.status == FindingStatus.OPEN.value,
        ).delete(synchronize_session=False)

    def _get_link(self, asset_id: AssetId, cve_id: str) -> AssetCVE | None:
        return (
            self.db.query(AssetCVE)
            .filter(AssetCVE.asset_id == asset_id, AssetCVE.cve_id == cve_id)
            .first()
        )


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
