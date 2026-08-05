import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.concurrency import run_in_threadpool
from packaging.version import InvalidVersion, Version
from sqlalchemy.orm import Session

from app.database.models import Asset, CVE, AssetCVE
from app.services.nist_nvd import nist_client, NvdUnavailableError
from app.services.enrichment import enrichment_service
from app.services.osv import osv_client
from app.models import AssetResponse

logger = logging.getLogger(__name__)


def _nvd_concurrency_limit() -> int:
    """Max concurrent NVD requests. Without an API key NVD allows only 5 req/30s,
    so keep the fan-out small; an API key (50 req/30s) allows much more.
    """
    override = os.getenv("NVD_MAX_CONCURRENCY", "")
    if override.isdigit() and int(override) > 0:
        return int(override)
    return 10 if nist_client.api_key else 3


class CVEMonitoringService:
    def __init__(self, db: Session):
        self.db = db
        self.nist_client = nist_client
        # Bounds every NVD request made through this service (per request), so
        # fanning out across assets and CPEs never bursts past NVD's rate limit.
        self._nvd_semaphore: asyncio.Semaphore | None = None

    def _nvd_sem(self) -> asyncio.Semaphore:
        if self._nvd_semaphore is None:
            self._nvd_semaphore = asyncio.Semaphore(_nvd_concurrency_limit())
        return self._nvd_semaphore

    async def monitor_all_assets(self) -> dict[str, Any]:
        try:
            assets = self.db.query(Asset).all()

            monitoring_results = {
                "timestamp": datetime.now(timezone.utc),
                "total_assets_monitored": len(assets),
                "asset_results": [],
                "summary": {
                    "new_vulnerabilities": 0,
                    "critical_vulnerabilities": 0,
                    "high_vulnerabilities": 0,
                    "medium_vulnerabilities": 0,
                    "low_vulnerabilities": 0,
                },
            }

            for asset in assets:
                logger.info(f"Monitoring asset: {asset.name} v{asset.version}")
                asset_result = await self._monitor_single_asset(asset)
                monitoring_results["asset_results"].append(asset_result)

                monitoring_results["summary"]["new_vulnerabilities"] += len(
                    asset_result.get("new_vulnerabilities", [])
                )
                for vuln in asset_result.get("new_vulnerabilities", []):
                    severity = vuln.get("severity", "").upper()
                    if severity == "CRITICAL":
                        monitoring_results["summary"]["critical_vulnerabilities"] += 1
                    elif severity == "HIGH":
                        monitoring_results["summary"]["high_vulnerabilities"] += 1
                    elif severity == "MEDIUM":
                        monitoring_results["summary"]["medium_vulnerabilities"] += 1
                    elif severity == "LOW":
                        monitoring_results["summary"]["low_vulnerabilities"] += 1

            monitoring_results["asset_results"].sort(
                key=lambda asset_result: max(
                    [
                        vuln.get("publish_date", "1900-01-01T00:00:00")
                        for vuln in asset_result.get("new_vulnerabilities", [])
                    ],
                    default="1900-01-01T00:00:00",
                ),
                reverse=True,
            )

            return monitoring_results

        except Exception as e:
            logger.error(f"Error in monitor_all_assets: {e}")
            return {"error": str(e), "timestamp": datetime.now(timezone.utc)}

    async def _monitor_single_asset(self, asset: Asset) -> dict[str, Any]:
        try:
            asset_response = AssetResponse.model_validate(asset)

            # Monitoring must never miss a freshly published CVE, so it bypasses
            # the read cache (the fetched result still refreshes it for readers).
            current_vulnerabilities = await self._get_asset_vulnerabilities(
                asset_response, use_cache=False
            )

            candidate_cve_ids = [
                vuln["cve_id"] for vuln in current_vulnerabilities if vuln.get("cve_id")
            ]
            existing_cve_ids = self._existing_cve_ids_for_asset(
                asset, candidate_cve_ids
            )

            new_vulnerabilities = []
            for vuln in current_vulnerabilities:
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id not in existing_cve_ids:
                    new_vulnerabilities.append(vuln)

                    await self._store_cve_for_asset(vuln, asset)

            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_version": asset.version,
                "user_email": asset.user_email,
                "total_vulnerabilities": len(current_vulnerabilities),
                "new_vulnerabilities": new_vulnerabilities,
                "existing_vulnerabilities": len(existing_cve_ids),
                "last_monitored": datetime.now(timezone.utc),
                "status": "success",
            }

        except Exception as e:
            logger.error(f"Error monitoring asset {asset.name}: {e}")
            return {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "error": str(e),
                "status": "error",
            }

    async def get_user_vulnerabilities(
        self, user_email: str, days: int = 0, severity_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """All vulnerabilities across a user's assets, via the precise engine.

        Uses the same CPE-aware, version-filtered, KEV/EPSS-enriched matching as
        the per-asset endpoint, tagging each finding with its originating asset.
        """
        assets = self.db.query(Asset).filter(Asset.user_email == user_email).all()

        async def for_asset(asset: Asset) -> list[dict[str, Any]]:
            asset_response = AssetResponse.model_validate(asset)
            vulns = await self._get_asset_vulnerabilities(
                asset_response, days=days, severity_filter=severity_filter
            )
            return [
                {
                    **vuln,
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "asset_version": asset.version,
                }
                for vuln in vulns
            ]

        # Assets are independent read-only lookups; run them concurrently. The
        # shared per-service semaphore keeps total NVD concurrency bounded.
        per_asset = await asyncio.gather(*(for_asset(asset) for asset in assets))
        return [vuln for asset_vulns in per_asset for vuln in asset_vulns]

    async def _get_asset_vulnerabilities(
        self,
        asset: AssetResponse,
        days: int = 0,
        severity_filter: str | None = None,
        use_cache: bool = True,
    ) -> list[dict[str, Any]]:
        pub_start_date = None
        pub_end_date = None
        if days > 0:
            pub_end_date = datetime.now(timezone.utc)
            pub_start_date = pub_end_date - timedelta(days=days)

        cpe_name = self._full_cpe(asset.cpe)
        if cpe_name:
            cpe_names = [cpe_name]
        else:
            cpe_names = await self._resolve_cpes(asset)

        if cpe_names:
            vulnerabilities = []
            nvd_failed = False
            # Independent CPE lookups run concurrently: an asset resolving to
            # several vendor CPEs is the common slow case.
            results = await asyncio.gather(
                *(
                    self._search_by_cpe(
                        asset, cpe, pub_start_date, pub_end_date, use_cache
                    )
                    for cpe in cpe_names
                )
            )
            for found, failed in results:
                vulnerabilities.extend(found)
                nvd_failed = nvd_failed or failed
        else:
            vulnerabilities, nvd_failed = await self._search_by_keyword(
                asset, pub_start_date, pub_end_date, use_cache
            )

        # Secondary source: OSV.dev covers language-package ecosystems that
        # NVD/CPE matches poorly. Best-effort; merged and deduplicated below.
        ecosystem = getattr(asset, "ecosystem", None)
        if ecosystem:
            osv_found = await run_in_threadpool(
                osv_client.search, ecosystem, asset.name, asset.version
            )
            vulnerabilities.extend(osv_found)

        if nvd_failed and not vulnerabilities:
            raise NvdUnavailableError(
                "Could not retrieve vulnerabilities: the NVD service is unavailable."
            )

        vulnerabilities_list = list(
            {
                vuln.get("cve_id"): vuln
                for vuln in sorted(vulnerabilities, key=self._finding_richness)
                if vuln.get("cve_id")
            }.values()
        )

        if severity_filter:
            severity_filter_upper = severity_filter.upper()
            vulnerabilities_list = [
                vuln
                for vuln in vulnerabilities_list
                if vuln.get("severity", "").upper() == severity_filter_upper
            ]

        await run_in_threadpool(enrichment_service.enrich, vulnerabilities_list)

        # Actively-exploited (KEV) findings sort first, then by severity, then by
        # exploit probability (EPSS), then recency.
        vulnerabilities_list.sort(
            key=lambda x: (
                -int(bool(x.get("kev"))),
                -self._get_severity_priority(x.get("severity")),
                -(x.get("epss") or 0.0),
                -(
                    datetime.fromisoformat(
                        x.get("publish_date", "1900-01-01T00:00:00").replace(
                            "Z", "+00:00"
                        )
                    ).timestamp()
                    if x.get("publish_date")
                    else 0
                ),
                -(
                    datetime.fromisoformat(
                        x.get("modified_date", "1900-01-01T00:00:00").replace(
                            "Z", "+00:00"
                        )
                    ).timestamp()
                    if x.get("modified_date")
                    else 0
                ),
            )
        )

        self._attach_triage_status(asset, vulnerabilities_list)
        return vulnerabilities_list

    def _attach_triage_status(
        self, asset: AssetResponse, findings: list[dict[str, Any]]
    ) -> None:
        """Tag each finding with its triage status from ``asset_cves`` (or 'open')."""
        status_map: dict[str, str] = {}
        cve_ids = [f["cve_id"] for f in findings if f.get("cve_id")]
        if self.db is not None and cve_ids:
            rows = (
                self.db.query(AssetCVE.cve_id, AssetCVE.status)
                .filter(AssetCVE.asset_id == asset.id, AssetCVE.cve_id.in_(cve_ids))
                .all()
            )
            status_map = {cve_id: status for cve_id, status in rows}
        for finding in findings:
            cve_id = finding.get("cve_id")
            finding["status"] = status_map.get(cve_id, "open") if cve_id else "open"

    def set_finding_status(
        self, asset: Asset, cve_id: str, status: str, notes: str | None
    ) -> AssetCVE:
        """Create or update the triage status of an (asset, CVE) finding."""
        link = (
            self.db.query(AssetCVE)
            .filter(AssetCVE.asset_id == asset.id, AssetCVE.cve_id == cve_id)
            .first()
        )
        if link is None:
            # The finding may not have been persisted yet; ensure the shared CVE
            # row exists (FK) then create the link.
            if not self.db.query(CVE).filter(CVE.id == cve_id).first():
                self.db.add(CVE(id=cve_id))
            link = AssetCVE(asset_id=asset.id, cve_id=cve_id)
            self.db.add(link)
        link.status = status  # type: ignore[assignment]
        link.notes = notes  # type: ignore[assignment]
        self.db.commit()
        self.db.refresh(link)
        return link

    async def _search_by_cpe(
        self,
        asset: AssetResponse,
        cpe_name: str,
        pub_start_date: datetime | None,
        pub_end_date: datetime | None,
        use_cache: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Precise lookup: let NVD resolve the CPE (version-aware, server-side).

        When an asset declares a CPE we trust NVD's matching engine, which
        evaluates version ranges in each CVE configuration. This avoids both the
        100-result keyword cap and the false positives/negatives of text search.
        """
        try:
            async with self._nvd_sem():
                cves = await run_in_threadpool(
                    self.nist_client.search_cves,
                    cpe_name=cpe_name,
                    results_per_page=2000,
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
        return [self._vuln_dict(cve, reason) for cve in cves], False

    async def _search_by_keyword(
        self,
        asset: AssetResponse,
        pub_start_date: datetime | None,
        pub_end_date: datetime | None,
        use_cache: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Fallback lookup when no CPE is known: keyword search + local filtering.

        Less precise than a CPE lookup (NVD keyword search is capped at 100
        results and matches free text), so each candidate is filtered locally by
        product identity and version range via ``_is_relevant_to_asset``.
        """
        queries = self._build_search_queries(asset)
        results = await asyncio.gather(
            *(
                self._search_one_keyword(
                    asset, query, pub_start_date, pub_end_date, use_cache
                )
                for query in queries
            )
        )
        vulnerabilities: list[dict[str, Any]] = []
        nvd_failed = False
        for found, failed in results:
            vulnerabilities.extend(found)
            nvd_failed = nvd_failed or failed
        return vulnerabilities, nvd_failed

    async def _search_one_keyword(
        self,
        asset: AssetResponse,
        query: str,
        pub_start_date: datetime | None,
        pub_end_date: datetime | None,
        use_cache: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        try:
            async with self._nvd_sem():
                cves = await run_in_threadpool(
                    self.nist_client.search_cves,
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
            self._vuln_dict(cve, f"Matches asset name '{asset.name}'")
            for cve in cves
            if self._is_relevant_to_asset(cve, asset)
        ], False

    def _vuln_dict(self, cve, reason: str) -> dict[str, Any]:
        return {
            "cve_id": cve.cve_id,
            "summary": cve.summary,
            "severity": cve.severity,
            "score": cve.score,
            "publish_date": cve.publish_date.isoformat() if cve.publish_date else None,
            "modified_date": cve.modified_date.isoformat()
            if cve.modified_date
            else None,
            "relevance_reason": reason,
            "cve_url": f"https://www.cve.org/CVERecord?id={cve.cve_id}",
        }

    @staticmethod
    def _full_cpe(cpe: str | None) -> str | None:
        """Return a well-formed CPE 2.3 name usable with NVD's ``cpeName`` filter.

        NVD requires a fully specified 13-component CPE 2.3 URI. User-provided
        values are trimmed and padded with ``*`` so that partial CPEs such as
        ``cpe:2.3:a:f5:nginx:1.24.0`` still resolve. Anything that is not a CPE
        2.3 string returns ``None`` so the caller falls back to keyword search.
        """
        if not cpe:
            return None
        cpe = cpe.strip()
        if not cpe.lower().startswith("cpe:2.3:"):
            return None
        parts = cpe.split(":")
        if len(parts) < 13:
            parts += ["*"] * (13 - len(parts))
        elif len(parts) > 13:
            parts = parts[:13]
        return ":".join(parts)

    async def _resolve_cpes(self, asset: AssetResponse) -> list[str]:
        """Best-effort: turn an asset name into precise CPE names via NVD.

        When the user did not provide a CPE, look the product name up in the
        NVD CPE dictionary and build a fully specified CPE for each matching
        vendor/product pair, injecting the asset version so NVD can evaluate
        version ranges server-side. Returns an empty list (caller falls back to
        keyword search) when the name cannot be resolved or NVD is unreachable.
        """
        if not asset.name:
            return []
        try:
            async with self._nvd_sem():
                cpe_names = await run_in_threadpool(
                    self.nist_client.find_cpe_names, asset.name
                )
        except Exception as e:
            logger.warning(f"CPE resolution failed for '{asset.name}': {e}")
            return []

        name_variants = {self._normalize(v) for v in self._name_variants(asset.name)}
        version = (asset.version or "*").strip() or "*"
        seen: set[tuple[str, str]] = set()
        resolved: list[str] = []
        for cpe_name in cpe_names:
            parts = cpe_name.split(":")
            if len(parts) < 13:
                continue
            part, vendor, product = parts[2], parts[3], parts[4]
            # Applications, operating systems and hardware. Keep only an exact
            # (separator-insensitive) match on the product or on the
            # "vendor+product" pair, so "nginx" never pulls in
            # "nginx_proxy_manager" while "apache http server" still resolves to
            # apache:http_server.
            if part not in {"a", "o", "h"}:
                continue
            if name_variants.isdisjoint(self._identity_norms(vendor, product)):
                continue
            key = (vendor, product)
            if key in seen:
                continue
            seen.add(key)
            resolved.append(
                ":".join(["cpe", "2.3", part, vendor, product, version] + ["*"] * 7)
            )
            if len(resolved) >= 5:
                break
        return resolved

    @staticmethod
    def _normalize(value: str) -> str:
        return value.replace(" ", "").replace("-", "").replace("_", "")

    @staticmethod
    def _finding_richness(vuln: dict[str, Any]) -> tuple[bool, bool]:
        """Rank a finding so a duplicate with severity/score wins the merge."""
        return (vuln.get("severity") is not None, vuln.get("score") is not None)

    @staticmethod
    def _identity_norms(vendor: str, product: str) -> set[str]:
        """Separator-insensitive identity tokens for a CPE vendor/product pair.

        Includes the bare product and the ``vendor+product`` concatenation so a
        display name such as "Apache HTTP Server" matches ``apache:http_server``
        without loosening into substring matches.
        """
        normalize = CVEMonitoringService._normalize
        product_norm = normalize(product.lower())
        vendor_norm = normalize(vendor.lower())
        norms = {product_norm}
        if vendor_norm:
            norms.add(vendor_norm + product_norm)
        return norms

    def _get_severity_priority(self, severity: str | None) -> int:
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return severity_map.get(severity or "LOW", 1)

    def _build_search_queries(self, asset: AssetResponse) -> list[str]:
        queries = []

        if asset.name:
            queries.append(asset.name)
            name_lower = asset.name.lower()
            queries.append(name_lower.replace(" ", ""))
            queries.append(name_lower.replace(" ", "-"))

        if asset.cpe:
            queries.append(asset.cpe)

        if asset.version and asset.name:
            queries.append(f"{asset.name} {asset.version}")

        return list(set(queries))

    def _is_relevant_to_asset(self, cve_data, asset: AssetResponse) -> bool:
        name_variants = self._name_variants(asset.name)
        affected = getattr(cve_data, "affected_products", None) or []
        product_matches = [
            product
            for product in affected
            if self._cpe_matches_name(product.get("cpe", ""), name_variants)
        ]

        # Authoritative path: the CVE declares affected CPEs. Trust them over
        # free-text. This filters out third-party products that merely mention
        # the asset name in their description (e.g. "X, used in NGINX, ...").
        if affected:
            if not product_matches:
                return False
            # Version-aware filtering: keep the CVE only if the asset version
            # falls inside a vulnerable range (e.g. drops "nginx before 1.13.6"
            # for an asset running 1.24.0).
            if asset.version:
                return any(
                    self._version_affected(asset.version, product)
                    for product in product_matches
                )
            return True

        # No CPE data at all: best-effort relevance from the free-text summary.
        summary_lower = cve_data.summary.lower()
        if name_variants and any(variant in summary_lower for variant in name_variants):
            return True

        if asset.version and asset.version.lower() in summary_lower:
            return True

        return False

    @staticmethod
    def _name_variants(name: str | None) -> set[str]:
        if not name:
            return set()
        lower = name.lower()
        return {lower, lower.replace(" ", ""), lower.replace(" ", "-")}

    @staticmethod
    def _cpe_matches_name(cpe: str, name_variants: set[str]) -> bool:
        if not cpe or not name_variants:
            return False
        parts = cpe.split(":")
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
        if len(parts) <= 4:
            return False
        vendor = parts[3]
        product = parts[4]
        if not product:
            return False

        normalize = CVEMonitoringService._normalize
        name_norms = {normalize(variant.lower()) for variant in name_variants}
        identity = CVEMonitoringService._identity_norms(vendor, product)
        # Exact (separator-insensitive) match on product or vendor+product, so
        # "nginx" does NOT match "nginx_proxy_manager" but "apache http server"
        # matches apache:http_server.
        return not name_norms.isdisjoint(identity)

    @staticmethod
    def _version_affected(asset_version: str, product: dict) -> bool:
        try:
            version = Version(asset_version)
        except InvalidVersion:
            # Unparseable asset version: do not drop the CVE.
            return True

        bounds = [
            (product.get("version_start"), "ge"),  # versionStartIncluding
            (product.get("version_start_excluding"), "gt"),  # versionStartExcluding
            (product.get("version_end"), "lt"),  # versionEndExcluding
            (product.get("version_end_including"), "le"),  # versionEndIncluding
        ]
        has_range = False
        for raw_bound, op in bounds:
            if not raw_bound:
                continue
            has_range = True
            try:
                bound = Version(str(raw_bound))
            except InvalidVersion:
                continue
            if op == "ge" and not version >= bound:
                return False
            if op == "gt" and not version > bound:
                return False
            if op == "lt" and not version < bound:
                return False
            if op == "le" and not version <= bound:
                return False
        if has_range:
            return True

        # No range: fall back to the exact version encoded in the CPE, if any.
        parts = product.get("cpe", "").split(":")
        cpe_version = parts[5] if len(parts) > 5 else ""
        if cpe_version and cpe_version not in ("*", "-"):
            try:
                return Version(cpe_version) == version
            except InvalidVersion:
                return cpe_version == asset_version

        # Product-level CPE with no version info: assume affected.
        return True

    def _existing_cve_ids_for_asset(
        self, asset: Asset, candidate_cve_ids: list[str]
    ) -> set[str]:
        """CVE ids already linked to this asset, among the given candidates.

        Only the candidate ids (the CVEs just found for the asset) are queried
        against the ``asset_cves`` association, so this never scans the whole
        table and the per-asset link carries no tenant data.
        """
        if not candidate_cve_ids:
            return set()
        rows = (
            self.db.query(AssetCVE.cve_id)
            .filter(
                AssetCVE.asset_id == asset.id,
                AssetCVE.cve_id.in_(candidate_cve_ids),
            )
            .all()
        )
        return {row[0] for row in rows}

    async def _store_cve_for_asset(self, vuln_data: dict[str, Any], asset: Asset):
        cve_id = vuln_data.get("cve_id")
        if not cve_id:
            return
        try:
            existing_cve = self.db.query(CVE).filter(CVE.id == cve_id).first()
            if not existing_cve:
                publish_date = None
                if vuln_data.get("publish_date"):
                    try:
                        publish_date = datetime.fromisoformat(
                            vuln_data.get("publish_date", "").replace("Z", "+00:00")
                        )
                    except Exception:
                        pass

                # The shared CVE row holds only global metadata; the per-asset
                # link lives in ``asset_cves`` (no tenant data here).
                self.db.add(
                    CVE(
                        id=cve_id,
                        summary=vuln_data.get("summary", ""),
                        severity=vuln_data.get("severity"),
                        score=vuln_data.get("score"),
                        publish_date=publish_date,
                    )
                )

            link_exists = (
                self.db.query(AssetCVE)
                .filter(AssetCVE.asset_id == asset.id, AssetCVE.cve_id == cve_id)
                .first()
            )
            if not link_exists:
                self.db.add(AssetCVE(asset_id=asset.id, cve_id=cve_id))

            self.db.commit()
            logger.info(f"Stored new CVE: {cve_id} for asset {asset.name}")

        except Exception as e:
            logger.error(f"Error storing CVE {cve_id}: {e}")
            self.db.rollback()

    async def get_monitoring_report(
        self, user_email: str, days: int = 7
    ) -> dict[str, Any]:
        try:
            user_assets = (
                self.db.query(Asset).filter(Asset.user_email == user_email).all()
            )

            if not user_assets:
                return {
                    "message": "No assets registered for monitoring",
                    "total_assets": 0,
                }

            logger.info(
                f"Generating monitoring report for {len(user_assets)} assets over {days} days"
            )

            all_relevant_cves = []

            for asset in user_assets:
                logger.info(f"Searching for CVEs related to asset: {asset.name}")

                asset_response = AssetResponse.model_validate(asset)
                search_queries = self._build_search_queries(asset_response)

                try:
                    logger.info(
                        f"Searching for CVEs related to {asset.name} in last {days} days"
                    )

                    # Search for each query term separately to ensure we don't miss anything
                    for query in search_queries:
                        logger.info(f"Searching with keyword: {query}")
                        query_cves = await run_in_threadpool(
                            self.nist_client.search_cves,
                            keyword=query,
                            pub_start_date=datetime.now(timezone.utc)
                            - timedelta(days=days),
                            pub_end_date=datetime.now(timezone.utc),
                            results_per_page=100,
                        )
                        logger.info(
                            f"Found {len(query_cves)} CVEs for keyword '{query}'"
                        )

                        for cve_data in query_cves:
                            cve_dict = {
                                "cve_id": cve_data.cve_id,
                                "summary": cve_data.summary,
                                "severity": cve_data.severity,
                                "score": cve_data.score,
                                "publish_date": cve_data.publish_date.isoformat()
                                if cve_data.publish_date
                                else None,
                                "asset_name": asset.name,
                                "matched_query": query,
                                "cve_url": f"https://www.cve.org/CVERecord?id={cve_data.cve_id}",
                            }

                            # Avoid duplicates
                            if not any(
                                existing.get("cve_id") == cve_dict.get("cve_id")
                                for existing in all_relevant_cves
                            ):
                                all_relevant_cves.append(cve_dict)
                                logger.info(
                                    f"Found relevant CVE: {cve_dict.get('cve_id')} (matched: {query})"
                                )

                except Exception as e:
                    logger.error(f"Error fetching CVEs for asset {asset.name}: {e}")
                    continue

            logger.info(f"Found {len(all_relevant_cves)} relevant CVEs")

            all_relevant_cves.sort(
                key=lambda x: (
                    -self._get_severity_priority(x.get("severity")),
                    -(
                        datetime.fromisoformat(
                            x.get("publish_date", "1900-01-01T00:00:00").replace(
                                "Z", "+00:00"
                            )
                        ).timestamp()
                        if x.get("publish_date")
                        else 0
                    ),
                )
            )
            logger.info(
                "Sorted CVEs by severity (highest first), then by publish date (most recent first)"
            )

            report = {
                "user_email": user_email,
                "report_period_days": days,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_assets": len(user_assets),
                "assets": [
                    {
                        "id": asset.id,
                        "name": asset.name,
                        "version": asset.version,
                        "description": asset.description,
                    }
                    for asset in user_assets
                ],
                "recent_vulnerabilities": all_relevant_cves[:50],
                "vulnerability_summary": {
                    "total_recent": len(all_relevant_cves),
                    "critical": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "CRITICAL"
                    ),
                    "high": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "HIGH"
                    ),
                    "medium": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "MEDIUM"
                    ),
                    "low": sum(
                        1
                        for cve in all_relevant_cves
                        if str(cve.get("severity", "")).upper() == "LOW"
                    ),
                },
                "data_source": "NIST NVD API (live data)",
            }

            return report

        except Exception as e:
            logger.error(f"Error generating monitoring report: {e}")
            return {"error": str(e)}
