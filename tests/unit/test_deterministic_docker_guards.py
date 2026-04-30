# tested-by: tests/unit/test_deterministic_docker_guards.py
"""Deterministic guards for Docker runtime and test pin drift (#263).

These tests detect version drift between Dockerfile.test and the canonical
sources (pyproject.toml and uv.lock). Docker pins must match the project's
dependency declarations to ensure reproducible builds.

Bug: #263 — Docker runtime and test pins drift from pyproject and uv.lock
Parent: #229
Epic: #146
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import re
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _read_text(relative_path: str) -> str:
    return (_REPO / relative_path).read_text(encoding="utf-8")


def _load_toml(relative_path: str) -> dict[str, object]:
    with (_REPO / relative_path).open("rb") as file:
        data = tomllib.load(file)
    assert isinstance(data, dict), f"{relative_path} must parse to a TOML mapping"
    return data


def _extract_dockerfile_pip_versions(dockerfile_content: str) -> dict[str, str]:
    """Extract package==version pins from 'uv pip install' commands in Dockerfile."""
    versions: dict[str, str] = {}
    # Match lines like: RUN --security=insecure uv pip install mypy==1.15.0 pyarrow==24.0.0
    for line in dockerfile_content.splitlines():
        if "uv pip install" in line or "pip install" in line:
            # Find all package==version patterns
            matches = re.findall(r"([a-zA-Z0-9_-]+)==([\d.]+)", line)
            for pkg, version in matches:
                versions[pkg.lower()] = version
    return versions


def _extract_uv_lock_version(lock_content: str, package_name: str) -> str | None:
    """Extract version of a package from uv.lock content."""
    # Look for [[package]] name = "pkg" followed by version = "X.Y.Z"
    pattern = rf'\[\[package\]\]\s*\nname = "{re.escape(package_name)}"\s*\nversion = "([\d.]+)"'
    match = re.search(pattern, lock_content)
    if match:
        return match.group(1)
    return None


def _extract_pyproject_version(pyproject: dict[str, object], package_name: str) -> str | None:
    """Extract version of a package from pyproject.toml data."""
    pkg_lower = package_name.lower()

    # Check main dependencies
    deps = pyproject.get("project", {}).get("dependencies", [])
    if isinstance(deps, list):
        for dep in deps:
            if isinstance(dep, str) and dep.lower().startswith(f"{pkg_lower}=="):
                match = re.search(rf"{pkg_lower}==([\d.]+)", dep, re.IGNORECASE)
                if match:
                    return match.group(1)

    # Check optional dependencies
    opt_deps = pyproject.get("project", {}).get("optional-dependencies", {})
    if isinstance(opt_deps, dict):
        for _group, packages in opt_deps.items():
            if isinstance(packages, list):
                for dep in packages:
                    if isinstance(dep, str) and dep.lower().startswith(f"{pkg_lower}=="):
                        match = re.search(rf"{pkg_lower}==([\d.]+)", dep, re.IGNORECASE)
                        if match:
                            return match.group(1)

    # Check dependency groups (dev, etc.)
    dep_groups = pyproject.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for _group, packages in dep_groups.items():
            if isinstance(packages, list):
                for dep in packages:
                    if isinstance(dep, str) and dep.lower().startswith(f"{pkg_lower}=="):
                        match = re.search(rf"{pkg_lower}==([\d.]+)", dep, re.IGNORECASE)
                        if match:
                            return match.group(1)

    return None


def test_docker_pyarrow_matches_pyproject():
    """Dockerfile.test pyarrow version must match pyproject.toml parquet extra."""
    dockerfile = _read_text("Dockerfile.test")
    pyproject = _load_toml("pyproject.toml")

    docker_versions = _extract_dockerfile_pip_versions(dockerfile)
    pyproject_version = _extract_pyproject_version(pyproject, "pyarrow")

    assert "pyarrow" in docker_versions, (
        "pyarrow must be pinned in Dockerfile.test (via uv pip install). "
        "This is required for parquet integration tests."
    )

    docker_version = docker_versions.get("pyarrow")

    if pyproject_version is None:
        pytest.fail(
            "pyarrow not found in pyproject.toml. Expected in [project.optional-dependencies] "
            "under 'parquet' group (e.g., 'parquet = [\"pyarrow==X.Y.Z\"]')."
        )

    assert docker_version == pyproject_version, (
        f"Dockerfile.test pyarrow version drift: Dockerfile has {docker_version}, "
        f"pyproject.toml specifies {pyproject_version}. "
        f"Update Dockerfile.test to use pyarrow=={pyproject_version}"
    )


def test_docker_pyarrow_matches_uv_lock():
    """Dockerfile.test pyarrow version must match uv.lock resolved version."""
    dockerfile = _read_text("Dockerfile.test")
    uv_lock = _read_text("uv.lock")

    docker_versions = _extract_dockerfile_pip_versions(dockerfile)
    lock_version = _extract_uv_lock_version(uv_lock, "pyarrow")

    assert "pyarrow" in docker_versions, (
        "pyarrow must be pinned in Dockerfile.test (via uv pip install). "
        "This is required for parquet integration tests."
    )

    docker_version = docker_versions.get("pyarrow")

    if lock_version is None:
        pytest.fail(
            "pyarrow not found in uv.lock. Run 'uv lock' to ensure the lock file "
            "reflects the dependency tree including [parquet] extra."
        )

    assert docker_version == lock_version, (
        f"Dockerfile.test pyarrow version drift: Dockerfile has {docker_version}, "
        f"uv.lock specifies {lock_version}. "
        f"Update Dockerfile.test to use pyarrow=={lock_version} or re-run 'uv lock'"
    )


def test_docker_mypy_matches_pyproject():
    """Dockerfile.test mypy version must match pyproject.toml dev dependency (if present)."""
    dockerfile = _read_text("Dockerfile.test")
    pyproject = _load_toml("pyproject.toml")

    docker_versions = _extract_dockerfile_pip_versions(dockerfile)
    pyproject_version = _extract_pyproject_version(pyproject, "mypy")

    assert "mypy" in docker_versions, (
        "mypy must be pinned in Dockerfile.test (via uv pip install). "
        "This is required for type-check integration tests."
    )

    docker_version = docker_versions.get("mypy")

    if pyproject_version is None:
        # mypy is not in pyproject.toml - this is the bug we want to detect
        pytest.fail(
            f"mypy=={docker_version} is pinned in Dockerfile.test but NOT found in "
            f"pyproject.toml. Add mypy to [dependency-groups] dev section to make it "
            f"a managed dependency, or update Dockerfile.test to use the correct version. "
            f"See issue #263."
        )

    assert docker_version == pyproject_version, (
        f"Dockerfile.test mypy version drift: Dockerfile has {docker_version}, "
        f"pyproject.toml specifies {pyproject_version}. "
        f"Update Dockerfile.test to use mypy=={pyproject_version}"
    )


def test_docker_mypy_matches_uv_lock():
    """Dockerfile.test mypy version must match uv.lock resolved version."""
    dockerfile = _read_text("Dockerfile.test")
    uv_lock = _read_text("uv.lock")

    docker_versions = _extract_dockerfile_pip_versions(dockerfile)
    lock_version = _extract_uv_lock_version(uv_lock, "mypy")

    assert "mypy" in docker_versions, (
        "mypy must be pinned in Dockerfile.test (via uv pip install). "
        "This is required for type-check integration tests."
    )

    docker_version = docker_versions.get("mypy")

    if lock_version is None:
        # mypy is not in uv.lock - this is the bug we want to detect
        pytest.fail(
            f"mypy=={docker_version} is pinned in Dockerfile.test but NOT found in "
            f"uv.lock. Add mypy to [dependency-groups] dev section in pyproject.toml "
            f"and run 'uv lock' to include it in the locked dependency tree. "
            f"See issue #263."
        )

    assert docker_version == lock_version, (
        f"Dockerfile.test mypy version drift: Dockerfile has {docker_version}, "
        f"uv.lock specifies {lock_version}. "
        f"Update Dockerfile.test to use mypy=={lock_version} or re-run 'uv lock'"
    )


def test_dockerfile_pins_all_have_canonical_source():
    """Every package pinned in Dockerfile.test must exist in pyproject.toml or uv.lock."""
    dockerfile = _read_text("Dockerfile.test")
    pyproject = _load_toml("pyproject.toml")
    uv_lock = _read_text("uv.lock")

    docker_versions = _extract_dockerfile_pip_versions(dockerfile)

    missing_packages: list[str] = []

    for pkg in docker_versions:
        in_pyproject = _extract_pyproject_version(pyproject, pkg) is not None
        in_lock = _extract_uv_lock_version(uv_lock, pkg) is not None

        if not in_pyproject and not in_lock:
            missing_packages.append(
                f"  - {pkg}=={docker_versions[pkg]} (not in pyproject.toml or uv.lock)"
            )

    if missing_packages:
        pytest.fail(
            f"Dockerfile.test pins packages not managed by the project:\n"
            f"{chr(10).join(missing_packages)}\n\n"
            f"All Dockerfile.test pinned packages must be declared in pyproject.toml "
            f"and locked in uv.lock. See issue #263."
        )
