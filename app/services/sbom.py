"""Turn a CycloneDX or SPDX (JSON) SBOM into the packages it lists.

Each component is identified by its package URL (purl), whose type gives the
OSV ecosystem, so imported assets are matched against OSV.dev out of the box.
"""

from dataclasses import dataclass, field
from typing import Any, Iterator, Optional
from urllib.parse import unquote

MAX_COMPONENTS = 2000

# purl type -> (OSV ecosystem, separator between namespace and name).
_ECOSYSTEMS: dict[str, tuple[str, str]] = {
    "pypi": ("PyPI", "/"),
    "npm": ("npm", "/"),
    "golang": ("Go", "/"),
    "maven": ("Maven", ":"),
    "cargo": ("crates.io", "/"),
    "gem": ("RubyGems", "/"),
    "nuget": ("NuGet", "/"),
    "composer": ("Packagist", "/"),
    "pub": ("Pub", "/"),
    "hex": ("Hex", "/"),
}


class SbomError(ValueError):
    """The document is not an SBOM this importer understands."""


@dataclass(frozen=True)
class Package:
    name: str
    version: Optional[str]
    ecosystem: str


@dataclass
class ParsedSbom:
    project: Optional[str]
    packages: list[Package] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


def parse_purl(purl: str) -> Optional[tuple[str, str, Optional[str]]]:
    """Return (type, full name, version) or None if this is not a purl."""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    version = None
    at = rest.rfind("@")
    # An "@" before the last "/" belongs to an npm scope, not to the version.
    if at > rest.rfind("/"):
        rest, version = rest[:at], unquote(rest[at + 1 :]) or None
    purl_type, _, path = rest.partition("/")
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments:
        return None
    purl_type = purl_type.lower()
    separator = _ECOSYSTEMS.get(purl_type, ("", "/"))[1]
    namespace = "/".join(segments[:-1])
    name = f"{namespace}{separator}{segments[-1]}" if namespace else segments[-1]
    return purl_type, name, version


def parse_sbom(document: Any) -> ParsedSbom:
    if not isinstance(document, dict):
        raise SbomError("The SBOM must be a JSON object")
    if document.get("bomFormat") == "CycloneDX":
        metadata = document.get("metadata") or {}
        project = _text((metadata.get("component") or {}).get("name"))
        entries = _cyclonedx_entries(document.get("components"))
    elif "spdxVersion" in document:
        project = _text(document.get("name"))
        entries = _spdx_entries(document.get("packages"))
    else:
        raise SbomError("Unsupported format: expected CycloneDX or SPDX JSON")

    result = ParsedSbom(project=project)
    seen: set[Package] = set()
    for count, (label, purl) in enumerate(entries, start=1):
        if count > MAX_COMPONENTS:
            raise SbomError(f"The SBOM lists more than {MAX_COMPONENTS} components")
        parsed = parse_purl(purl) if purl else None
        if parsed is None or parsed[0] not in _ECOSYSTEMS:
            result.unsupported.append(purl or label)
            continue
        purl_type, name, version = parsed
        package = Package(name, version, _ECOSYSTEMS[purl_type][0])
        if package not in seen:
            seen.add(package)
            result.packages.append(package)
    return result


def _cyclonedx_entries(components: Any) -> Iterator[tuple[str, str]]:
    for component in components if isinstance(components, list) else []:
        if not isinstance(component, dict):
            continue
        yield _text(component.get("name")) or "?", _text(component.get("purl")) or ""
        yield from _cyclonedx_entries(component.get("components"))


def _spdx_entries(packages: Any) -> Iterator[tuple[str, str]]:
    for package in packages if isinstance(packages, list) else []:
        if not isinstance(package, dict):
            continue
        refs = package.get("externalRefs")
        purl = next(
            (
                _text(ref.get("referenceLocator"))
                for ref in (refs if isinstance(refs, list) else [])
                if isinstance(ref, dict) and ref.get("referenceType") == "purl"
            ),
            None,
        )
        yield _text(package.get("name")) or "?", purl or ""


def _text(value: Any) -> Optional[str]:
    return (value.strip() or None) if isinstance(value, str) else None
