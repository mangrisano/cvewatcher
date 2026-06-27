"""Periodic CVE monitoring driven by APScheduler.

The scheduler is opt-in: it only runs when MONITOR_ENABLED is truthy, so the
application (and the test suite) never reaches out to the NVD API unless
explicitly configured to do so.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.database.connection import SessionLocal
from app.services.cve_monitoring import CVEMonitoringService
from app.services.notifications import Notifier, build_notifiers_from_env, dispatch

logger = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


def _extract_new_findings(monitoring_results: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for asset_result in monitoring_results.get("asset_results", []):
        for vuln in asset_result.get("new_vulnerabilities", []):
            findings.append(
                {
                    "asset_name": asset_result.get("asset_name"),
                    "asset_version": asset_result.get("asset_version"),
                    "user_email": asset_result.get("user_email"),
                    "cve_id": vuln.get("cve_id"),
                    "severity": vuln.get("severity"),
                    "score": vuln.get("score"),
                    "cve_url": vuln.get("cve_url"),
                    "publish_date": vuln.get("publish_date"),
                }
            )
    return findings


async def run_monitoring_cycle(
    notifiers: Optional[list[Notifier]] = None,
) -> list[dict[str, Any]]:
    """Run one monitoring pass over all assets and notify about new findings."""
    if notifiers is None:
        notifiers = build_notifiers_from_env()

    db = SessionLocal()
    try:
        service = CVEMonitoringService(db)
        results = await service.monitor_all_assets()
        findings = _extract_new_findings(results)
        logger.info("Monitoring cycle complete: %d new finding(s)", len(findings))
        dispatch(findings, notifiers)
        return findings
    except Exception as e:
        logger.error("Monitoring cycle failed: %s", e)
        return []
    finally:
        db.close()


def start_scheduler() -> Optional[AsyncIOScheduler]:
    global _scheduler

    if os.getenv("MONITOR_ENABLED", "false").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        logger.info("Periodic monitoring disabled (set MONITOR_ENABLED=true to enable)")
        return None

    interval_minutes = int(os.getenv("MONITOR_INTERVAL_MINUTES", "360"))
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        run_monitoring_cycle,
        trigger="interval",
        minutes=interval_minutes,
        id="cve_monitoring",
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("Periodic monitoring started (every %d minute(s))", interval_minutes)
    return _scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Periodic monitoring stopped")
