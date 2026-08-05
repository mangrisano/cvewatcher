"""User-scoped vulnerability findings: global summary and export.

A "finding" is a CVE that affects one of the user's assets. These endpoints
aggregate findings across all of the user's assets and, by default, hide
suppressed ones (status fixed / false_positive / accepted_risk).
"""

import csv
import io
import json
import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.dependencies import get_current_user
from app.models import SUPPRESSED_STATUSES, FindingsSummary, VulnerabilityResponse
from app.services.cve_monitoring import CVEMonitoringService
from app.services.nist_nvd import NvdUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["Findings"])

_EXPORT_COLUMNS = [
    "cve_id",
    "asset_name",
    "asset_version",
    "severity",
    "score",
    "kev",
    "epss",
    "status",
    "publish_date",
    "cve_url",
    "summary",
]


async def _collect_findings(
    db: Session,
    user_email: str,
    days: int,
    include_suppressed: bool,
    use_cache: bool = True,
) -> list[dict]:
    service = CVEMonitoringService(db)
    findings = await service.get_user_vulnerabilities(
        user_email, days=days, use_cache=use_cache
    )
    if not include_suppressed:
        findings = [f for f in findings if f.get("status") not in SUPPRESSED_STATUSES]
    return findings


@router.get("", response_model=FindingsSummary)
async def findings_summary(
    days: int = Query(default=0, ge=0, description="0 = all time"),
    include_suppressed: bool = Query(default=False),
    refresh: bool = Query(
        default=False, description="Bypass caches for a live re-check"
    ),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = current_user.get("sub")
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid user token")

    try:
        findings = await _collect_findings(
            db, user_email, days, include_suppressed, use_cache=not refresh
        )
    except NvdUnavailableError as e:
        raise HTTPException(
            status_code=503,
            detail=f"NVD service is currently unavailable. Please retry later. ({e})",
        )

    by_severity = Counter((f.get("severity") or "UNKNOWN") for f in findings)
    by_status = Counter((f.get("status") or "open") for f in findings)
    return FindingsSummary(
        total=len(findings),
        kev=sum(1 for f in findings if f.get("kev")),
        by_severity=dict(by_severity),
        by_status=dict(by_status),
        findings=[VulnerabilityResponse(**f) for f in findings],
    )


@router.get("/export")
async def export_findings(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    days: int = Query(default=0, ge=0),
    include_suppressed: bool = Query(default=False),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_email = current_user.get("sub")
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid user token")

    try:
        findings = await _collect_findings(db, user_email, days, include_suppressed)
    except NvdUnavailableError as e:
        raise HTTPException(
            status_code=503,
            detail=f"NVD service is currently unavailable. Please retry later. ({e})",
        )

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
