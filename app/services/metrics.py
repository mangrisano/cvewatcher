"""Prometheus metrics rendered from the database (no live NVD calls).

Metrics are aggregate across all users (no per-tenant labels), so the endpoint
can be scraped without authentication like a normal ``/metrics`` target.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import Asset, AssetCVE, CVE


def _gauge(name: str, help_text: str, samples: list[tuple[dict, int]]) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    for labels, value in samples:
        if labels:
            rendered = ",".join(f'{key}="{val}"' for key, val in labels.items())
            lines.append(f"{name}{{{rendered}}} {value}")
        else:
            lines.append(f"{name} {value}")
    return lines


def render_metrics(db: Session) -> str:
    assets_total = db.query(func.count(Asset.id)).scalar() or 0
    findings_total = db.query(func.count(AssetCVE.cve_id)).scalar() or 0

    severity_rows = (
        db.query(CVE.severity, func.count(AssetCVE.cve_id))
        .join(AssetCVE, AssetCVE.cve_id == CVE.id)
        .group_by(CVE.severity)
        .all()
    )
    status_rows = (
        db.query(AssetCVE.status, func.count(AssetCVE.cve_id))
        .group_by(AssetCVE.status)
        .all()
    )

    lines: list[str] = []
    lines += _gauge(
        "cvewatcher_assets_total", "Registered assets.", [({}, assets_total)]
    )
    lines += _gauge(
        "cvewatcher_findings_total",
        "Asset-CVE findings.",
        [({}, findings_total)],
    )
    lines += _gauge(
        "cvewatcher_findings_by_severity",
        "Findings grouped by CVE severity.",
        [({"severity": sev or "UNKNOWN"}, count) for sev, count in severity_rows],
    )
    lines += _gauge(
        "cvewatcher_findings_by_status",
        "Findings grouped by triage status.",
        [({"status": status or "open"}, count) for status, count in status_rows],
    )
    return "\n".join(lines) + "\n"
