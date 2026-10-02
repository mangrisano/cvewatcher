"""Vulnerability sources: where findings for an asset come from.

Each source turns an asset into a list of finding dicts. The monitoring
service queries every configured source and merges the results, so a new
feed is added by implementing :class:`VulnerabilitySource`, not by editing the
service.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

from app.config import get_settings
from app.services import matching
from app.services.nist_nvd import NistNvdClient, NvdUnavailableError, nist_client
from app.services.osv import OsvClient, OsvError, osv_client

logger = logging.getLogger(__name__)

Finding = dict[str, Any]


@dataclass(frozen=True)
class SourceResult:
    findings: list[Finding] = field(default_factory=list)
    # The source could not be reached at all (as opposed to "found nothing").
    unavailable: bool = False


class VulnerabilitySource(Protocol):
    async def search(
        self,
        asset,
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        use_cache: bool,
    ) -> SourceResult: ...


def nvd_concurrency_limit(client: NistNvdClient) -> int:
    """Max concurrent NVD requests. Without an API key NVD allows only 5 req/30s,
    so keep the fan-out small; an API key (50 req/30s) allows much more.
    """
    return get_settings().nvd_max_concurrency or (
        10 if getattr(client, "api_key", None) else 3
    )


class NvdSource:
    """NIST NVD: precise CPE lookups, with keyword search as the fallback."""

    def __init__(self, client: NistNvdClient):
        self.client = client
        # Bounds every NVD request made through this source, so fanning out
        # across assets and CPEs never bursts past NVD's rate limit.
        self._semaphore: asyncio.Semaphore | None = None

    def _sem(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(nvd_concurrency_limit(self.client))
        return self._semaphore

    async def search(
        self,
        asset,
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        use_cache: bool,
    ) -> SourceResult:
        cpe_name = matching.full_cpe(asset.cpe)
        if not cpe_name and getattr(asset, "ecosystem", None):
            # A package with an ecosystem is covered by OSV; guessing its CPE
            # costs NVD requests and mostly finds nothing.
            return SourceResult()
        cpe_names = [cpe_name] if cpe_name else await self._resolve_cpes(asset)

        if cpe_names:
            # Independent CPE lookups run concurrently: an asset resolving to
            # several vendor CPEs is the common slow case.
            searches = (
                self._search_by_cpe(cpe, pub_start_date, pub_end_date, use_cache)
                for cpe in cpe_names
            )
        else:
            searches = (
                self._search_one_keyword(
                    asset, query, pub_start_date, pub_end_date, use_cache
                )
                for query in matching.build_search_queries(asset)
            )

        findings: list[Finding] = []
        unavailable = False
        for found, failed in await asyncio.gather(*searches):
            findings.extend(found)
            unavailable = unavailable or failed
        return SourceResult(findings, unavailable)

    async def _resolve_cpes(self, asset) -> list[str]:
        """Best-effort: turn an asset name into precise CPE names via NVD.

        Returns an empty list (caller falls back to keyword search) when the
        name cannot be resolved or NVD is unreachable.
        """
        if not asset.name:
            return []
        try:
            async with self._sem():
                cpe_names = await self.client.find_cpe_names(asset.name)
        except Exception as e:
            logger.warning(f"CPE resolution failed for '{asset.name}': {e}")
            return []

        return matching.cpes_for_asset(cpe_names, asset.name, asset.version)

    async def _search_by_cpe(
        self,
        cpe_name: str,
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        use_cache: bool,
    ) -> tuple[list[Finding], bool]:
        """Precise lookup: let NVD resolve the CPE (version-aware, server-side).

        NVD's matching engine evaluates version ranges in each CVE
        configuration, avoiding both the 100-result keyword cap and the false
        positives/negatives of text search.
        """
        try:
            async with self._sem():
                cves = await self.client.search_cves(
                    cpe_name=cpe_name,
                    all_pages=True,
                    pub_start_date=pub_start_date,
                    pub_end_date=pub_end_date,
                    use_cache=use_cache,
                )
        except NvdUnavailableError as e:
            logger.error(f"NVD unavailable for CPE {cpe_name}: {e}")
            return [], True
        except Exception as e:
            logger.error(f"Error searching CPE {cpe_name}: {e}")
            return [], False

        reason = f"NVD matched CPE '{cpe_name}'"
        return [_finding(cve, reason) for cve in cves], False

    async def _search_one_keyword(
        self,
        asset,
        query: str,
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        use_cache: bool,
    ) -> tuple[list[Finding], bool]:
        """Keyword search (capped at 100 by NVD), filtered locally by identity
        and version range via ``matching.is_relevant``.
        """
        try:
            async with self._sem():
                cves = await self.client.search_cves(
                    keyword=query,
                    results_per_page=100,
                    pub_start_date=pub_start_date,
                    pub_end_date=pub_end_date,
                    use_cache=use_cache,
                )
        except NvdUnavailableError as e:
            logger.error(f"NVD unavailable while searching for {query}: {e}")
            return [], True
        except Exception as e:
            logger.error(f"Error searching for {query}: {e}")
            return [], False

        return [
            _finding(cve, f"Matches asset name '{asset.name}'")
            for cve in cves
            if matching.is_relevant(cve, asset)
        ], False


class OsvSource:
    """OSV.dev: language and distribution packages that NVD/CPE matches poorly.

    Only for assets that declare an ecosystem; a failed query reports the
    source as unavailable. OSV has no publication-date filter, so a requested
    window is applied here on each advisory's ``published`` date.
    """

    def __init__(self, client: OsvClient):
        self.client = client

    async def search(
        self,
        asset,
        pub_start_date: Optional[datetime],
        pub_end_date: Optional[datetime],
        use_cache: bool,
    ) -> SourceResult:
        ecosystem = getattr(asset, "ecosystem", None)
        if not ecosystem:
            return SourceResult()
        try:
            findings = await self.client.search(ecosystem, asset.name, asset.version)
        except OsvError:
            return SourceResult(unavailable=True)
        if pub_start_date or pub_end_date:
            findings = [
                f
                for f in findings
                if _published_within(
                    f.get("publish_date"), pub_start_date, pub_end_date
                )
            ]
        return SourceResult(findings)


def _published_within(
    value: Optional[str], start: Optional[datetime], end: Optional[datetime]
) -> bool:
    """Whether an ISO timestamp falls in [start, end]; unknown dates do not."""
    if not value:
        return False
    try:
        published = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    return (start is None or published >= start) and (end is None or published <= end)


def default_sources() -> list[VulnerabilitySource]:
    """NVD first, then OSV; fresh instances so each caller gets its own NVD limit."""
    return [NvdSource(nist_client), OsvSource(osv_client)]


def _finding(cve, reason: str) -> Finding:
    return {
        "cve_id": cve.cve_id,
        "summary": cve.summary,
        "severity": cve.severity,
        "score": cve.score,
        "publish_date": cve.publish_date.isoformat() if cve.publish_date else None,
        "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
        "relevance_reason": reason,
        "cve_url": f"https://www.cve.org/CVERecord?id={cve.cve_id}",
    }
