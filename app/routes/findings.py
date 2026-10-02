"""User-scoped vulnerability findings: global summary and export.

A "finding" is a CVE that affects one of the user's assets. Findings are read
from the database, as stored by the last scan; ``refresh=true`` scans first.
Suppressed ones (status fixed / false_positive / accepted_risk) are hidden by
default.
"""

import csv
import io
import json
import logging
from enum import StrEnum
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Asset
from app.dependencies import (
    count_live_lookup,
    get_current_user,
    get_monitoring_service,
)
from app.models import FindingsSummary, FindingStatus, VulnerabilityResponse
from app.services.cve_monitoring import CVEMonitoringService
from app.services.findings_query import (
    FindingFilters,
    SortKey,
    query_findings,
    scan_state,
)
from app.services.nist_nvd import MAX_DATE_RANGE_DAYS
from app.services.scanning import scan_and_alert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["Findings"])


class SeverityFilter(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


_EXPORT_COLUMNS = [
    "cve_id",
    "asset_name",
    "asset_version",
    "asset_ecosystem",
    "severity",
    "score",
    "kev",
    "epss",
    "status",
    "publish_date",
    "cve_url",
    "summary",
]


def _user_email(current_user: dict) -> str:
    user_email = current_user.get("sub")
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid user token")
    return user_email


@router.get("", response_model=FindingsSummary)
async def findings_summary(
    days: int = Query(
        default=0, ge=0, le=MAX_DATE_RANGE_DAYS, description="0 = all time"
    ),
    include_suppressed: bool = Query(default=False),
    severity: Optional[SeverityFilter] = Query(default=None),
    status: Optional[FindingStatus] = Query(default=None),
    q: Optional[str] = Query(
        default=None,
        max_length=100,
        description="Search CVE id, asset name or ecosystem",
    ),
    sort: Optional[SortKey] = Query(
        default=None, description="Default: KEV, severity, EPSS, then newest"
    ),
    order: Literal["asc", "desc"] = Query(default="desc"),
    limit: int = Query(default=100, ge=0, le=500, description="0 = counts only"),
    offset: int = Query(default=0, ge=0),
    refresh: bool = Query(
        default=False, description="Scan all your assets before reading"
    ),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: CVEMonitoringService = Depends(get_monitoring_service),
):
    user_email = _user_email(current_user)
    if refresh:
        count_live_lookup(user_email)
        assets = db.query(Asset).filter(Asset.user_email == user_email).all()
        await scan_and_alert(db, service, assets)

    filters = FindingFilters(
        days=days,
        include_suppressed=include_suppressed,
        severity=severity.value if severity else None,
        status=status.value if status else None,
        search=q.strip() if q and q.strip() else None,
        sort=sort,
        descending=order == "desc",
    )
    page = query_findings(db, user_email, filters, limit=limit, offset=offset)
    last_scan, unscanned, total_assets = scan_state(db, user_email)
    return FindingsSummary(
        total=page.total,
        kev=page.kev,
        by_severity=page.by_severity,
        by_status=page.by_status,
        matched=page.matched,
        limit=limit,
        offset=offset,
        last_scan=last_scan,
        unscanned_assets=unscanned,
        total_assets=total_assets,
        findings=[VulnerabilityResponse(**f) for f in page.findings],
    )


@router.get("/export")
def export_findings(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    days: int = Query(default=0, ge=0, le=MAX_DATE_RANGE_DAYS),
    include_suppressed: bool = Query(default=False),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = _user_email(current_user)
    findings = query_findings(
        db,
        user_email,
        FindingFilters(days=days, include_suppressed=include_suppressed),
    ).findings

    if format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow({key: finding.get(key) for key in _EXPORT_COLUMNS})
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )

    payload = [
        VulnerabilityResponse(**finding).model_dump(mode="json") for finding in findings
    ]
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )
