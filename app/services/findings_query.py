"""Read side of findings: the user's current findings, straight from the database.

Scans write ``asset_cves`` and ``cves``; this module pages, filters, sorts and
counts them in SQL, so reading never waits on NVD or OSV.dev.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, get_args

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Query, Session

from app.database.models import CVE, Asset, AssetCVE
from app.models import SUPPRESSED_STATUSES, FindingStatus
from app.services.findings_repository import visible_link
from app.services.severity import KNOWN_SEVERITIES, band_rank, severity_band

SortKey = Literal["cve_id", "asset_name", "severity", "score", "kev", "epss", "status"]
SORT_KEYS = get_args(SortKey)

_KNOWN = sorted(KNOWN_SEVERITIES)
_STATUS = func.coalesce(AssetCVE.status, FindingStatus.OPEN.value)
_SEVERITY_RANK = case(
    *((func.upper(CVE.severity) == name, band_rank(name)) for name in _KNOWN),
    else_=0,
)
_IN_KEV = case((CVE.kev.is_(True), 1), else_=0)
_SORT_COLUMNS = {
    "cve_id": AssetCVE.cve_id,
    "asset_name": func.lower(Asset.name),
    "severity": _SEVERITY_RANK,
    "score": func.coalesce(CVE.score, -1),
    "kev": _IN_KEV,
    "epss": func.coalesce(CVE.epss, -1),
    "status": _STATUS,
}


@dataclass(frozen=True)
class FindingFilters:
    days: int = 0
    include_suppressed: bool = False
    severity: Optional[str] = None
    status: Optional[str] = None
    search: Optional[str] = None
    sort: Optional[str] = None
    descending: bool = True
    asset_id: Optional[Any] = None


@dataclass
class FindingsPage:
    # Counts cover every active finding; ``matched`` also applies the filters.
    total: int = 0
    kev: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    matched: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)


def advisory_url(finding_id: str) -> str:
    if finding_id.startswith("CVE-"):
        return f"https://www.cve.org/CVERecord?id={finding_id}"
    return f"https://osv.dev/vulnerability/{finding_id}"


def query_findings(
    db: Session,
    user_email: str,
    filters: FindingFilters = FindingFilters(),
    limit: Optional[int] = None,
    offset: int = 0,
) -> FindingsPage:
    """The user's current findings: counts plus one sorted page (all if no limit)."""
    active = _active(db, user_email, filters)
    page = FindingsPage(
        total=active.count(),
        kev=active.filter(CVE.kev.is_(True)).count(),
    )
    # Grouped on the raw columns: Postgres rejects GROUP BY on an expression
    # whose bound parameters differ from the SELECT's.
    for severity, count in active.with_entities(CVE.severity, func.count()).group_by(
        CVE.severity
    ):
        band = severity_band(severity)
        page.by_severity[band] = page.by_severity.get(band, 0) + count
    for status, count in active.with_entities(AssetCVE.status, func.count()).group_by(
        AssetCVE.status
    ):
        name = status or FindingStatus.OPEN.value
        page.by_status[name] = page.by_status.get(name, 0) + count

    matching = _filtered(active, filters)
    page.matched = matching.count()
    if limit == 0:
        return page
    rows = matching.order_by(*_ordering(filters)).offset(offset)
    if limit is not None:
        rows = rows.limit(limit)
    page.findings = [_as_finding(link, cve, asset) for link, cve, asset in rows]
    return page


def scan_state(db: Session, user_email: str) -> tuple[Optional[datetime], int, int]:
    """Last full scan of the user's assets, how many never had one, and the total."""
    last_scan, unscanned, total = (
        db.query(
            func.max(Asset.last_scanned_at),
            func.sum(case((Asset.last_scanned_at.is_(None), 1), else_=0)),
            func.count(Asset.id),
        )
        .filter(Asset.user_email == user_email)
        .one()
    )
    # SQLite drops the zone of timezone-aware columns; the value is UTC.
    if last_scan is not None and last_scan.tzinfo is None:
        last_scan = last_scan.replace(tzinfo=timezone.utc)
    return last_scan, int(unscanned or 0), int(total or 0)


def _active(db: Session, user_email: str, filters: FindingFilters) -> Query:
    query = (
        db.query(AssetCVE, CVE, Asset)
        .join(CVE, CVE.id == AssetCVE.cve_id)
        .join(Asset, Asset.id == AssetCVE.asset_id)
        .filter(Asset.user_email == user_email, visible_link())
    )
    if not filters.include_suppressed:
        query = query.filter(_STATUS.notin_(SUPPRESSED_STATUSES))
    if filters.asset_id is not None:
        query = query.filter(AssetCVE.asset_id == filters.asset_id)
    if filters.days > 0:
        # cves.publish_date holds naive UTC.
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None)
        query = query.filter(CVE.publish_date >= cutoff - timedelta(days=filters.days))
    return query


def _filtered(query: Query, filters: FindingFilters) -> Query:
    if filters.severity == "UNKNOWN":
        query = query.filter(
            or_(CVE.severity.is_(None), func.upper(CVE.severity).notin_(_KNOWN))
        )
    elif filters.severity:
        query = query.filter(func.upper(CVE.severity) == filters.severity)
    if filters.status:
        query = query.filter(_STATUS == filters.status)
    if filters.search:
        escaped = (
            filters.search.lower()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        query = query.filter(
            or_(
                func.lower(AssetCVE.cve_id).like(pattern, escape="\\"),
                func.lower(Asset.name).like(pattern, escape="\\"),
            )
        )
    return query


def _ordering(filters: FindingFilters) -> list:
    # KEV first, then severity, exploit probability and recency.
    default = [
        _IN_KEV.desc(),
        _SEVERITY_RANK.desc(),
        func.coalesce(CVE.epss, -1).desc(),
        CVE.publish_date.is_(None),
        CVE.publish_date.desc(),
    ]
    # Unique tie-break so pages never repeat or skip rows.
    tie_break = [AssetCVE.asset_id, AssetCVE.cve_id]
    column = _SORT_COLUMNS.get(filters.sort or "")
    if column is None:
        return default + tie_break
    chosen = column.desc() if filters.descending else column.asc()
    return [chosen, *default, *tie_break]


def _as_finding(link: AssetCVE, cve: CVE, asset: Asset) -> dict[str, Any]:
    cve_id = str(link.cve_id)
    return {
        "cve_id": cve_id,
        "asset_id": asset.id,
        "asset_name": asset.name,
        "asset_version": asset.version,
        "severity": cve.severity,
        "score": cve.score,
        "summary": cve.summary,
        "publish_date": _iso(cve.publish_date),
        "modified_date": _iso(cve.modified_date),
        "cve_url": advisory_url(cve_id),
        "relevance_reason": link.relevance_reason,
        "kev": bool(cve.kev),
        "epss": cve.epss,
        "status": link.status or FindingStatus.OPEN.value,
    }


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value is not None else None
