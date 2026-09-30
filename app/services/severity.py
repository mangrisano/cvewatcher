"""CVSS score bands and severity ordering shared by every vulnerability source."""

from typing import Optional

_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
KNOWN_SEVERITIES = frozenset(_RANK)


def band_from_score(score: Optional[float]) -> Optional[str]:
    """Map a CVSS base score to CRITICAL/HIGH/MEDIUM/LOW (None when unscored)."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def severity_rank(severity: Optional[str]) -> int:
    """Sort weight of a severity; unknown severities rank with LOW."""
    return _RANK.get(severity or "LOW", 1)


def band_rank(severity: Optional[str]) -> int:
    """Rank of a severity band for comparisons; unknown ranks below LOW (0)."""
    return _RANK.get((severity or "").upper(), 0)


def severity_band(severity: Optional[str]) -> str:
    """The severity as one of the known bands, or ``UNKNOWN``."""
    band = (severity or "").upper()
    return band if band in _RANK else "UNKNOWN"
