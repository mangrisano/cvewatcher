"""Pure CVE-to-asset matching: CPE normalisation, identity and version ranges.

No I/O and no state: every function here depends only on its arguments, so the
matching rules can be tested and benchmarked without NVD or a database.
"""

from typing import Any, Iterable, Optional

from packaging.version import InvalidVersion, Version

# CPE "part" values worth resolving: applications, operating systems, hardware.
_CPE_PARTS = {"a", "o", "h"}
_MAX_RESOLVED_CPES = 5


def full_cpe(cpe: Optional[str]) -> Optional[str]:
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


def normalize(value: str) -> str:
    return value.replace(" ", "").replace("-", "").replace("_", "")


def finding_richness(vuln: dict[str, Any]) -> tuple[bool, bool]:
    """Rank a finding so a duplicate with severity/score wins the merge."""
    return (vuln.get("severity") is not None, vuln.get("score") is not None)


def identity_norms(vendor: str, product: str) -> set[str]:
    """Separator-insensitive identity tokens for a CPE vendor/product pair.

    Includes the bare product and the ``vendor+product`` concatenation so a
    display name such as "Apache HTTP Server" matches ``apache:http_server``
    without loosening into substring matches.
    """
    product_norm = normalize(product.lower())
    vendor_norm = normalize(vendor.lower())
    norms = {product_norm}
    if vendor_norm:
        norms.add(vendor_norm + product_norm)
    return norms


def name_variants(name: Optional[str]) -> set[str]:
    if not name:
        return set()
    lower = name.lower()
    return {lower, lower.replace(" ", ""), lower.replace(" ", "-")}


def cpes_for_asset(
    cpe_names: Iterable[str], name: str, version: Optional[str]
) -> list[str]:
    """Pick the dictionary CPEs that identify the asset, injecting its version.

    Keeps only an exact (separator-insensitive) match on the product or on the
    "vendor+product" pair, so "nginx" never pulls in "nginx_proxy_manager"
    while "apache http server" still resolves to apache:http_server. The asset
    version is injected so NVD can evaluate version ranges server-side.
    """
    wanted = {normalize(v) for v in name_variants(name)}
    version = (version or "*").strip() or "*"
    seen: set[tuple[str, str]] = set()
    resolved: list[str] = []
    for cpe_name in cpe_names:
        parts = cpe_name.split(":")
        if len(parts) < 13:
            continue
        part, vendor, product = parts[2], parts[3], parts[4]
        if part not in _CPE_PARTS:
            continue
        if wanted.isdisjoint(identity_norms(vendor, product)):
            continue
        key = (vendor, product)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(
            ":".join(["cpe", "2.3", part, vendor, product, version] + ["*"] * 7)
        )
        if len(resolved) >= _MAX_RESOLVED_CPES:
            break
    return resolved


def build_search_queries(asset) -> list[str]:
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


def cpe_matches_name(cpe: str, variants: set[str]) -> bool:
    if not cpe or not variants:
        return False
    parts = cpe.split(":")
    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    if len(parts) <= 4:
        return False
    vendor = parts[3]
    product = parts[4]
    if not product:
        return False

    name_norms = {normalize(variant.lower()) for variant in variants}
    # Exact (separator-insensitive) match on product or vendor+product, so
    # "nginx" does NOT match "nginx_proxy_manager" but "apache http server"
    # matches apache:http_server.
    return not name_norms.isdisjoint(identity_norms(vendor, product))


def version_affected(asset_version: str, product: dict) -> bool:
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


def is_relevant(cve_data, asset) -> bool:
    """Whether a keyword-search hit really concerns the asset (and its version)."""
    variants = name_variants(asset.name)
    affected = getattr(cve_data, "affected_products", None) or []
    product_matches = [
        product
        for product in affected
        if cpe_matches_name(product.get("cpe", ""), variants)
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
                version_affected(asset.version, product) for product in product_matches
            )
        return True

    # No CPE data at all: best-effort relevance from the free-text summary.
    summary_lower = cve_data.summary.lower()
    if variants and any(variant in summary_lower for variant in variants):
        return True

    if asset.version and asset.version.lower() in summary_lower:
        return True

    return False
