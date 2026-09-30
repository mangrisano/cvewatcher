"""Running scans outside the scheduler: on request, or in the background."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.connection import SessionLocal
from app.database.models import Asset
from app.services.alerts import deliver_alerts, extract_alerts
from app.services.cve_monitoring import CVEMonitoringService
from app.services.findings_repository import AssetId
from app.services.notifications import build_notifiers_from_env

logger = logging.getLogger(__name__)


async def scan_and_alert(
    db: Session, service: CVEMonitoringService, assets: list[Asset]
) -> list[dict[str, Any]]:
    """Scan the assets and alert on what changed."""
    results = await service.monitor_assets(assets)
    # A scan records new findings as seen: alert now or the scheduler never will.
    await deliver_alerts(
        db, extract_alerts({"asset_results": results}), build_notifiers_from_env()
    )
    return results


def scan_new_assets_enabled() -> bool:
    return get_settings().scan_new_assets


async def scan_in_background(asset_ids: list[AssetId]) -> None:
    """Scan freshly created or changed assets after the response is sent."""
    db = SessionLocal()
    try:
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        await scan_and_alert(db, CVEMonitoringService(db), assets)
    except Exception:
        logger.exception("Background scan failed")
    finally:
        db.close()
