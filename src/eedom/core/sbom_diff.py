"""SBOM-based dependency diffing — ecosystem-agnostic via Syft CycloneDX.
# tested-by: tests/unit/test_sbom_diff.py

Replaces per-ecosystem lockfile parsers with a single approach:
run Syft twice (base branch + PR branch), diff the CycloneDX SBOMs.
Works for every ecosystem Syft supports: PyPI, npm, Maven, Go, Cargo, OCI.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from packaging.version import InvalidVersion, Version

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    ecosystem: str
    purl: str | None = None


def parse_sbom_packages(sbom: dict) -> dict[str, PackageInfo]:
    """Extract packages from a CycloneDX JSON SBOM.

    Returns a dict keyed by "{ecosystem}:{name}" for easy diffing.
    """
    packages: dict[str, PackageInfo] = {}

    for component in sbom.get("components", []):
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl) or component.get("type", "library")

        if not name:
            continue

        key = f"{ecosystem}:{name}"
        packages[key] = PackageInfo(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or None,
        )

    return packages


def diff_sboms(before: dict, after: dict) -> list[dict]:
    """Diff two CycloneDX SBOMs and return package changes.

    Returns list of dicts with keys:
        action: added | removed | upgraded | downgraded
        package: package name
        ecosystem: pypi | npm | maven | golang | cargo | etc.
        old_version: str | None
        new_version: str | None
        purl: str | None
    """
    before_pkgs = parse_sbom_packages(before)
    after_pkgs = parse_sbom_packages(after)

    changes: list[dict] = []
    all_keys = set(before_pkgs.keys()) | set(after_pkgs.keys())

    for key in sorted(all_keys):
        old = before_pkgs.get(key)
        new = after_pkgs.get(key)

        if new and not old:
            changes.append(
                {
                    "action": "added",
                    "package": new.name,
                    "ecosystem": new.ecosystem,
                    "old_version": None,
                    "new_version": new.version,
                    "purl": new.purl,
                }
            )
        elif old and not new:
            changes.append(
                {
                    "action": "removed",
                    "package": old.name,
                    "ecosystem": old.ecosystem,
                    "old_version": old.version,
                    "new_version": None,
                    "purl": old.purl,
                }
            )
        elif old and new and old.version != new.version:
            action = _classify_version_change(old.version, new.version)
            changes.append(
                {
                    "action": action,
                    "package": new.name,
                    "ecosystem": new.ecosystem,
                    "old_version": old.version,
                    "new_version": new.version,
                    "purl": new.purl,
                }
            )

    logger.info(
        "sbom_diff_complete",
        before_count=len(before_pkgs),
        after_count=len(after_pkgs),
        added=sum(1 for c in changes if c["action"] == "added"),
        removed=sum(1 for c in changes if c["action"] == "removed"),
        upgraded=sum(1 for c in changes if c["action"] == "upgraded"),
        downgraded=sum(1 for c in changes if c["action"] == "downgraded"),
    )

    return changes


def _classify_version_change(old_ver: str, new_ver: str) -> str:
    try:
        return "upgraded" if Version(old_ver) < Version(new_ver) else "downgraded"
    except InvalidVersion:
        logger.warning(
            "version_parse_failed",
            old_version=old_ver,
            new_version=new_ver,
        )
        return "upgraded"


_PURL_ECOSYSTEM_MAP: dict[str, str] = {
    "pkg:pypi/": "pypi",
    "pkg:npm/": "npm",
    "pkg:maven/": "maven",
    "pkg:golang/": "golang",
    "pkg:cargo/": "cargo",
    "pkg:gem/": "gem",
    "pkg:nuget/": "nuget",
    "pkg:hex/": "hex",
    "pkg:composer/": "composer",
    "pkg:cocoapods/": "cocoapods",
    "pkg:swift/": "swift",
    "pkg:pub/": "pub",
    "pkg:deb/": "deb",
    "pkg:rpm/": "rpm",
    "pkg:apk/": "apk",
    "pkg:oci/": "oci",
    "pkg:docker/": "docker",
    "pkg:github/": "github",
}


def _ecosystem_from_purl(purl: str) -> str | None:
    if not purl:
        return None
    for prefix, ecosystem in _PURL_ECOSYSTEM_MAP.items():
        if purl.startswith(prefix):
            return ecosystem
    return None
