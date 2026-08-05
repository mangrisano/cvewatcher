"""Scheduled per-user email digest of active findings.

Reads persisted findings (the ``asset_cves`` association populated by the
monitoring cycle) so it never calls NVD, and emails each user a summary of
their active (non-suppressed) findings. Opt-in via ``DIGEST_ENABLED``.
"""

import logging
import os

from app.database.connection import SessionLocal
from app.database.models import Asset, AssetCVE, CVE
from app.models import SUPPRESSED_STATUSES
from app.services.notifications import send_email

logger = logging.getLogger(__name__)


def digest_enabled() -> bool:
    return os.getenv("DIGEST_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _format_digest(rows) -> str:
    lines = []
    for link, cve, asset in rows:
        version = f" v{asset.version}" if asset.version else ""
        lines.append(
            f"{cve.id} [{cve.severity or 'UNKNOWN'}] {asset.name}{version} "
            f"— status: {link.status}"
        )
    return "\n".join(lines)


def run_digest_cycle() -> int:
    """Email every user with active findings a summary. Returns emails sent."""
    if not digest_enabled():
        return 0

    db = SessionLocal()
    sent = 0
    try:
        emails = [row[0] for row in db.query(Asset.user_email).distinct().all()]
        for email in emails:
            rows = (
                db.query(AssetCVE, CVE, Asset)
                .join(CVE, CVE.id == AssetCVE.cve_id)
                .join(Asset, Asset.id == AssetCVE.asset_id)
                .filter(
                    Asset.user_email == email,
                    AssetCVE.status.notin_(SUPPRESSED_STATUSES),
                )
                .all()
            )
            if not rows:
                continue
            subject = f"CVE Watcher digest: {len(rows)} active finding(s)"
            if send_email([email], subject, _format_digest(rows)):
                sent += 1
        logger.info("Digest cycle complete: %d email(s) sent", sent)
        return sent
    except Exception as e:
        logger.error("Digest cycle failed: %s", e)
        return sent
    finally:
        db.close()
