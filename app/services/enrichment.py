"""Threat-intelligence enrichment for CVE findings.

Two independent, best-effort signals are layered on top of the raw NVD data to
help triage:

- **CISA KEV** (Known Exploited Vulnerabilities): a boolean flag telling whether
  a CVE is being actively exploited in the wild. The strongest prioritisation
  signal available — a KEV entry means "patch this now".
- **EPSS** (Exploit Prediction Scoring System, FIRST.org): a 0..1 probability
  that a CVE will be exploited in the next 30 days.

Both feeds are fetched over HTTP and cached in-process with a TTL. Every call is
wrapped so a network failure degrades gracefully: findings are simply returned
without the extra fields instead of failing the whole request. Enrichment can be
disabled entirely with ``ENRICH_ENABLED=false``.
"""

import logging
import os
import time
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"
# FIRST.org accepts a comma-separated list; keep batches modest to stay well
# within URL length limits.
EPSS_BATCH_SIZE = 100


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


class EnrichmentService:
    def __init__(self, timeout: int = 10, ttl_seconds: int = 6 * 3600):
        self.timeout = timeout
        self.ttl_seconds = ttl_seconds
        self._kev_ids: Optional[set[str]] = None
        self._kev_fetched_at: float = 0.0
        self._epss_cache: dict[str, float] = {}
        self._epss_fetched_at: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return _is_truthy(os.getenv("ENRICH_ENABLED", "true"))

    def kev_ids(self) -> set[str]:
        """Return the set of CVE ids in the CISA KEV catalog (cached, best-effort)."""
        now = time.monotonic()
        if self._kev_ids is not None and now - self._kev_fetched_at < self.ttl_seconds:
            return self._kev_ids

        try:
            response = httpx.get(KEV_FEED_URL, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("Could not refresh CISA KEV catalog: %s", e)
            # Serve the stale cache if we have one, otherwise an empty set.
            return self._kev_ids if self._kev_ids is not None else set()

        ids = {
            entry.get("cveID", "").strip().upper()
            for entry in payload.get("vulnerabilities", [])
            if entry.get("cveID")
        }
        self._kev_ids = ids
        self._kev_fetched_at = now
        logger.info("Loaded %d CVE ids from the CISA KEV catalog", len(ids))
        return ids

    def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Return ``{cve_id: epss}`` for the requested ids (cached, best-effort)."""
        now = time.monotonic()
        wanted = {cve_id.strip().upper() for cve_id in cve_ids if cve_id}
        missing = [
            cve_id
            for cve_id in wanted
            if cve_id not in self._epss_fetched_at
            or now - self._epss_fetched_at[cve_id] >= self.ttl_seconds
        ]

        for start in range(0, len(missing), EPSS_BATCH_SIZE):
            batch = missing[start : start + EPSS_BATCH_SIZE]
            self._fetch_epss_batch(batch, now)

        return {
            cve_id: self._epss_cache[cve_id]
            for cve_id in wanted
            if cve_id in self._epss_cache
        }

    def _fetch_epss_batch(self, batch: list[str], now: float) -> None:
        try:
            response = httpx.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning("Could not fetch EPSS scores: %s", e)
            return

        for entry in payload.get("data", []):
            cve_id = entry.get("cve", "").strip().upper()
            if not cve_id:
                continue
            try:
                self._epss_cache[cve_id] = float(entry.get("epss"))
            except (TypeError, ValueError):
                continue
            self._epss_fetched_at[cve_id] = now
        # Mark ids that FIRST.org did not return so we don't re-query them every
        # time (they simply have no published EPSS score yet).
        for cve_id in batch:
            self._epss_fetched_at.setdefault(cve_id, now)

    def enrich(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add ``kev`` and ``epss`` to each finding in place; best-effort.

        A failure in either feed leaves the corresponding field at its default
        (``kev=False`` / ``epss=None``) rather than raising.
        """
        if not findings or not self.enabled:
            for finding in findings:
                finding.setdefault("kev", False)
                finding.setdefault("epss", None)
            return findings

        cve_ids = [f.get("cve_id", "") for f in findings if f.get("cve_id")]
        kev_ids = self.kev_ids()
        epss = self.epss_scores(cve_ids)

        for finding in findings:
            cve_id = (finding.get("cve_id") or "").strip().upper()
            finding["kev"] = cve_id in kev_ids
            finding["epss"] = epss.get(cve_id)
        return findings


enrichment_service = EnrichmentService()
