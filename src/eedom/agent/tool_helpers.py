"""Internal helpers for GATEKEEPER agent tools.
# tested-by: tests/unit/test_agent_tools.py

Pipeline runner, diff parsing, manifest detection, path validation.
Scanner tools now route through PluginRegistry (eedom.plugins).
"""

from __future__ import annotations

import functools
import json
import re
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_MANIFEST_FILES: dict[str, str] = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "pyproject.toml": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "go.mod": "golang",
    "go.sum": "golang",
    "Gemfile": "gem",
    "Gemfile.lock": "gem",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "*.csproj": "nuget",
    "packages.config": "nuget",
    "Directory.Packages.props": "nuget",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
    "composer.json": "composer",
    "composer.lock": "composer",
    "mix.exs": "hex",
    "mix.lock": "hex",
    "Package.swift": "swift",
    "Podfile": "cocoapods",
    "Podfile.lock": "cocoapods",
}


_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.@\-/]+$")


def extract_changed_files(diff_text: str) -> list[str]:
    """Extract file paths from a unified diff, skipping deleted files."""
    files: list[str] = []
    lines = diff_text.split("\n")
    i = 0
    while i < len(lines):
        match = re.match(r"^diff --git a/.+ b/(.+)$", lines[i])
        if match:
            path = match.group(1)
            is_deleted = False
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("diff --git"):
                    break
                if lines[j] == "+++ /dev/null":
                    is_deleted = True
                    break
            if not is_deleted:
                files.append(path)
        i += 1
    return files


def validate_paths(changed_files: list[str], repo_path: str) -> list[str]:
    """Filter paths to only those safely inside the repo root."""
    root = Path(repo_path).resolve()
    safe: list[str] = []
    for f in changed_files:
        try:
            resolved = (root / f).resolve()
            if resolved.is_relative_to(root):
                safe.append(f)
            else:
                logger.warning("path_traversal_blocked", path=f)
        except (ValueError, OSError):
            logger.warning("path_invalid", path=f)
    return safe


def clean_package_name(name: str) -> str:
    """Strip absolute paths from package names."""
    if name.startswith("/"):
        return Path(name).name
    if "/" in name and not name.startswith("@") and not name.startswith("pkg:"):
        parts = Path(name)
        if parts.suffix in (".txt", ".lock", ".toml", ".json", ".yaml", ".yml"):
            return parts.name
    return name


def clean_triggered_rules(rules: list[str]) -> list[str]:
    """Remove per-package suffixes from triggered rules."""
    return [re.sub(r" for .+$", "", rule) for rule in rules]


def detect_manifest_changes(diff_text: str) -> dict[str, list[str]]:
    """Detect which manifest files changed, grouped by ecosystem."""
    changed = extract_changed_files(diff_text)
    by_eco: dict[str, list[str]] = {}
    for fpath in changed:
        basename = Path(fpath).name
        eco = _MANIFEST_FILES.get(basename)
        if eco:
            by_eco.setdefault(eco, []).append(fpath)
    return by_eco


@functools.cache
def get_agent_settings() -> object:
    """Load AgentSettings from environment. Cached for the process lifetime."""
    from eedom.agent.config import AgentSettings

    return AgentSettings()


def make_pipeline_config() -> object:
    """Build EedomSettings from AgentSettings."""
    from eedom.core.config import EedomSettings
    from eedom.core.models import OperatingMode

    agent_cfg = get_agent_settings()
    return EedomSettings(
        db_dsn=agent_cfg.db_dsn,
        operating_mode=OperatingMode.advise,
        evidence_path=str(agent_cfg.evidence_path),
        opa_policy_path=str(agent_cfg.opa_policy_path),
        enabled_scanners=agent_cfg.enabled_scanners,
        pipeline_timeout=agent_cfg.pipeline_timeout,
    )


def run_syft(repo_path: str, timeout: int = 120) -> dict:
    """Run Syft to generate a CycloneDX SBOM. Returns parsed JSON."""
    result = subprocess.run(
        ["syft", f"dir:{repo_path}", "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.stdout:
        return json.loads(result.stdout)
    return {"components": []}


def _generate_base_sbom(repo_path: str) -> dict:
    """Generate SBOM from the merge-base commit for accurate diffing."""
    try:
        base_ref = subprocess.run(
            ["git", "-C", repo_path, "merge-base", "HEAD", "origin/main"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        base_sha = base_ref.stdout.strip()
        if not base_sha:
            logger.info("sbom.no_merge_base", msg="Using empty baseline")
            return {"components": []}

        current_sha = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()

        subprocess.run(
            ["git", "-C", repo_path, "checkout", base_sha, "--quiet"],
            timeout=10,
            check=False,
        )
        try:
            base_sbom = run_syft(repo_path)
        finally:
            subprocess.run(
                ["git", "-C", repo_path, "checkout", current_sha, "--quiet"],
                timeout=10,
                check=False,
            )
        return base_sbom
    except Exception:
        logger.warning("sbom.base_generation_failed", msg="Using empty baseline")
        return {"components": []}


def run_pipeline(
    diff_text: str,
    pr_url: str,
    team: str,
    repo_path: str,
) -> tuple[list, list[dict], dict]:
    """Run the review pipeline. Returns (decisions, sbom_changes, raw_sbom)."""
    from eedom.core.models import OperatingMode
    from eedom.core.pipeline import ReviewPipeline
    from eedom.core.sbom_diff import diff_sboms

    config = make_pipeline_config()
    pipeline = ReviewPipeline(config)

    manifest_changes = detect_manifest_changes(diff_text)
    python_manifests = manifest_changes.pop("pypi", [])
    non_python_manifests = manifest_changes

    all_decisions: list = []
    sbom_changes: list[dict] = []
    raw_sbom: dict = {}

    if python_manifests:
        decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=OperatingMode.advise,
            repo_path=Path(repo_path),
        )
        all_decisions.extend(decisions)

    if non_python_manifests:
        try:
            raw_sbom = run_syft(repo_path)
            before_sbom = _generate_base_sbom(repo_path)
            sbom_changes = diff_sboms(before_sbom, raw_sbom)
            sbom_decisions = pipeline.evaluate_sbom(
                before_sbom=before_sbom,
                after_sbom=raw_sbom,
                pr_url=pr_url,
                team=team,
                mode=OperatingMode.advise,
                repo_path=Path(repo_path),
            )
            all_decisions.extend(sbom_decisions)
        except FileNotFoundError:
            logger.warning("evaluate.syft_not_installed")
        except subprocess.TimeoutExpired:
            logger.warning("evaluate.syft_timeout")
        except Exception:
            logger.exception("evaluate.sbom_path_failed")

    if not python_manifests and not non_python_manifests:
        all_decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=OperatingMode.advise,
            repo_path=Path(repo_path),
        )

    return all_decisions, sbom_changes, raw_sbom
