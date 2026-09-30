"""Periodic CVE monitoring driven by APScheduler.

The scheduler is opt-in: it only runs when MONITOR_ENABLED is truthy, so the
application (and the test suite) never reaches out to the NVD API unless
explicitly configured to do so.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.database.connection import SessionLocal
from app.config import get_settings
from app.services.alerts import deliver_alerts, extract_alerts
from app.services.cve_monitoring import CVEMonitoringService
from app.services.digest import digest_enabled, run_digest_cycle
from app.services.notifications import Notifier, build_notifiers_from_env

logger = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


async def run_monitoring_cycle(
    notifiers: Optional[list[Notifier]] = None,
) -> list[dict[str, Any]]:
    """Run one monitoring pass over all assets and send the resulting alerts.

    ``notifiers`` are the instance-wide channels (default: from the env).
    """
    if notifiers is None:
        notifiers = build_notifiers_from_env()

    db = SessionLocal()
    try:
        service = CVEMonitoringService(db)
        results = await service.monitor_all_assets()
        found = extract_alerts(results)
        logger.info("Monitoring cycle complete: %d alert(s)", len(found))
        await deliver_alerts(db, found, notifiers)
        return found
    except Exception as e:
        logger.error("Monitoring cycle failed: %s", e)
        return []
    finally:
        db.close()


def start_scheduler() -> Optional[AsyncIOScheduler]:
    global _scheduler

    settings = get_settings()
    monitor = settings.monitor_enabled
    digest = digest_enabled()
    if not monitor and not digest:
        logger.info("Periodic monitoring disabled (set MONITOR_ENABLED=true to enable)")
        return None

    _scheduler = AsyncIOScheduler()
    if monitor:
        interval_minutes = settings.monitor_interval_minutes
        _scheduler.add_job(
            run_monitoring_cycle,
            trigger="interval",
            minutes=interval_minutes,
            id="cve_monitoring",
            next_run_time=datetime.now(timezone.utc),
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "Periodic monitoring started (every %d minute(s))", interval_minutes
        )
    if digest:
        digest_interval = settings.digest_interval_minutes
        _scheduler.add_job(
            run_digest_cycle,
            trigger="interval",
            minutes=digest_interval,
            id="email_digest",
            max_instances=1,
            coalesce=True,
        )
        logger.info("Email digest started (every %d minute(s))", digest_interval)
    _scheduler.start()
    return _scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Periodic monitoring stopped")
