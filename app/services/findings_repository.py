"""Persistence of findings: the ``asset_cves`` links and the shared ``cves`` rows."""

import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import Column, and_, or_
from sqlalchemy.orm import Session

from app.database.models import CVE, Asset, AssetCVE
from app.models import FindingStatus
from app.services.severity import severity_band

logger = logging.getLogger(__name__)

# The 1.x-style models type ``Asset.id`` as a Column for static checkers.
AssetId = UUID | Column


def visible_link():
    """SQL condition for links still current: seen in the asset's last full scan.

    Assets never fully scanned show every link they have. Needs ``Asset`` joined.
    """
    return or_(
        Asset.last_scanned_at.is_(None),
        and_(
            AssetCVE.last_seen.is_not(None),
            AssetCVE.last_seen >= Asset.last_scanned_at,
        ),
    )


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

    def record(
        self,
        asset_id: AssetId,
        finding: dict[str, Any],
        kev_known: bool = False,
        seen_at: Optional[datetime] = None,
        link: Optional[AssetCVE] = None,
    ) -> AssetCVE:
        """Store a finding seen by a scan: refresh the CVE, create or touch the link.

        ``kev_known`` says whether the KEV catalog was available, so a missing
        catalog is not recorded as "not in KEV". Changes are committed by ``save``.
        """
        cve_id = finding["cve_id"]
        # The shared CVE row holds only global metadata; the per-asset link
        # lives in ``asset_cves`` (no tenant data here).
        cve = self.db.query(CVE).filter(CVE.id == cve_id).first()
        if cve is None:
            cve = CVE(id=cve_id)
            self.db.add(cve)
            # No ORM relationship orders the inserts: the link's FK needs this row.
            self.db.flush()
        for field in ("summary", "severity", "score", "epss"):
            if finding.get(field) is not None:
                setattr(cve, field, finding[field])
        published = _parse_date(finding.get("publish_date"))
        if published is not None:
            cve.publish_date = published  # type: ignore[assignment]
        if kev_known:
            cve.kev = bool(finding.get("kev"))  # type: ignore[assignment]

        if link is None:
            link = self._get_link(asset_id, cve_id)
        if link is None:
            link = AssetCVE(
                asset_id=asset_id,
                cve_id=cve_id,
                kev=bool(finding.get("kev")) if kev_known else None,
                severity=severity_band(finding.get("severity")),
            )
            self.db.add(link)
        link.last_seen = seen_at or datetime.now(timezone.utc)  # type: ignore[assignment]
        link.relevance_reason = finding.get("relevance_reason")  # type: ignore[assignment]
        return link

    def close_scan(self, asset: Asset, scanned_at: datetime) -> None:
        """Mark a complete scan: findings it did not see are gone.

        Untriaged ones are deleted; triaged ones are kept (hidden by
        ``visible_link``) so their status survives if they come back.
        """
        self.db.flush()
        asset.last_scanned_at = scanned_at  # type: ignore[assignment]
        self.db.query(AssetCVE).filter(
            AssetCVE.asset_id == asset.id,
            AssetCVE.status == FindingStatus.OPEN.value,
            or_(AssetCVE.last_seen.is_(None), AssetCVE.last_seen < scanned_at),
        ).delete(synchronize_session=False)

    def save(self) -> bool:
        """Commit the pending finding changes; best-effort. False if nothing was stored."""
        try:
            self.db.commit()
            return True
        except Exception as e:
            logger.error("Error saving findings: %s", e)
            self.db.rollback()
            return False

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
                self.db.flush()
            link = AssetCVE(
                asset_id=asset_id, cve_id=cve_id, last_seen=datetime.now(timezone.utc)
            )
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
    """Parse an ISO timestamp as naive UTC, the form ``cves.publish_date`` holds."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed
