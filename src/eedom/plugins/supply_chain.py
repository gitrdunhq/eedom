"""Supply chain plugin — unpinned deps + lockfile integrity + Docker latest-tag detection.
# tested-by: tests/unit/test_supply_chain_latest.py

Pure Python — no external binary needed.
"""

from __future__ import annotations

import hashlib
import json
import re
import textwrap
from pathlib import Path

import structlog
import yaml

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin

logger = structlog.get_logger(__name__)

_REVIEW_WIDTH = 88

_LOCKFILE_TO_MANIFEST: dict[str, list[str]] = {
    "package-lock.json": ["package.json"],
    "yarn.lock": ["package.json"],
    "pnpm-lock.yaml": ["package.json"],
    "uv.lock": ["pyproject.toml"],
    "poetry.lock": ["pyproject.toml"],
    "Pipfile.lock": ["Pipfile"],
    "Cargo.lock": ["Cargo.toml"],
    "go.sum": ["go.mod"],
    "Gemfile.lock": ["Gemfile"],
    "composer.lock": ["composer.json"],
}

# Matches: FROM [--platform=...] <image> [AS <stage>]
# Group 1: image reference (everything between FROM/platform flag and optional AS clause)
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE,
)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _wrap_review_text(text: str, width: int = _REVIEW_WIDTH) -> list[str]:
    normalized = " ".join(str(text).split())
    if not normalized:
        return []
    return textwrap.wrap(
        normalized,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [normalized]


def _is_dockerfile(name: str) -> bool:
    """Return True for Dockerfile* or *.dockerfile file names."""
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile")


def _is_compose(name: str) -> bool:
    """Return True for docker-compose*.yml / docker-compose*.yaml file names."""
    return (
        name.startswith("docker-compose") or name == "compose.yml" or name == "compose.yaml"
    ) and (name.endswith(".yml") or name.endswith(".yaml"))


def _image_is_floating(image: str) -> bool:
    """Return True if *image* resolves to an uncontrolled (latest-equivalent) tag.

    Pinned forms that are NOT floating:
      - foo:1.2.3          explicit semver-like tag
      - foo@sha256:<hex>   digest pin

    Floating forms:
      - foo                no tag at all (implicit latest)
      - foo:latest         explicit latest
    """
    if "@" in image:
        # digest-pinned — always safe
        return False
    if ":" in image:
        tag = image.split(":", 1)[1]
        return tag == "latest"
    # no tag separator → implicit latest
    return True


class SupplyChainPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "supply-chain"

    @property
    def description(self) -> str:
        return "Unpinned dependency detection + lockfile integrity + Docker latest-tag detection"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        names = {Path(f).name for f in files}
        manifests = {
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
            "Gemfile",
            "composer.json",
        }
        locks = set(_LOCKFILE_TO_MANIFEST.keys())
        if names & (manifests | locks):
            return True
        return any(_is_dockerfile(n) or _is_compose(n) for n in names)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        findings: list[dict] = []
        findings.extend(self._check_unpinned(repo_path))
        findings.extend(self._check_lockfiles(files, repo_path))

        for f in files:
            p = Path(f)
            full = repo_path / p if not p.is_absolute() else p
            try:
                full.resolve().relative_to(repo_path.resolve())
            except ValueError:
                logger.warning("supply_chain.path_traversal_blocked", file=f)
                continue
            if _is_dockerfile(p.name):
                findings.extend(self._check_dockerfile_latest(str(full)))
            elif _is_compose(p.name):
                findings.extend(self._check_compose_latest(str(full)))

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={
                "unpinned": sum(1 for f in findings if f.get("type") == "unpinned"),
                "lockfile_issues": sum(1 for f in findings if f.get("type") == "lockfile"),
                "docker_latest": sum(1 for f in findings if f.get("type") == "docker_latest"),
            },
        )

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def _check_dockerfile_latest(self, file_path: str) -> list[dict]:
        """Scan a Dockerfile for FROM lines that resolve to an implicit or explicit latest tag."""
        findings: list[dict] = []
        try:
            lines = Path(file_path).read_text().splitlines()
        except OSError:
            return findings

        for lineno, raw in enumerate(lines, start=1):
            m = _FROM_RE.match(raw)
            if not m:
                continue
            image = m.group(1)
            # Skip scratch (no meaningful tag concept) and ARG-based references
            if image.lower() == "scratch" or image.startswith("$"):
                continue
            if _image_is_floating(image):
                findings.append(
                    {
                        "type": "docker_latest",
                        "file": file_path,
                        "line": lineno,
                        "severity": "medium",
                        "description": (
                            f"Dockerfile FROM uses floating image `{image}` — "
                            "pin to a specific digest or version tag"
                        ),
                    }
                )

        return findings

    # ── Docker Compose ────────────────────────────────────────────────────────

    def _check_compose_latest(self, file_path: str) -> list[dict]:
        """Scan a Docker Compose file for service images that resolve to latest."""
        findings: list[dict] = []
        try:
            raw = Path(file_path).read_text()
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError):
            return findings

        if not isinstance(data, dict):
            return findings

        services = data.get("services") or {}
        if not isinstance(services, dict):
            return findings

        for _svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            image = svc.get("image")
            if not image or not isinstance(image, str):
                continue
            if _image_is_floating(image):
                findings.append(
                    {
                        "type": "docker_latest",
                        "file": file_path,
                        "service": _svc_name,
                        "severity": "medium",
                        "description": (
                            f"Compose service `{_svc_name}` uses floating image `{image}` — "
                            "pin to a specific digest or version tag"
                        ),
                    }
                )

        return findings

    # ── Unpinned deps ─────────────────────────────────────────────────────────

    def _check_unpinned(self, repo: Path) -> list[dict]:
        findings: list[dict] = []

        for pkg in repo.rglob("package.json"):
            if "node_modules" in str(pkg) or ".git" in str(pkg):
                continue
            rel = str(pkg.relative_to(repo))
            try:
                data = json.loads(pkg.read_text())
                for section in ("dependencies", "devDependencies"):
                    for name, ver in data.get(section, {}).items():
                        if self._is_floating_npm(ver):
                            findings.append(
                                {
                                    "type": "unpinned",
                                    "file": rel,
                                    "package": name,
                                    "version": ver,
                                    "ecosystem": "npm",
                                    "reason": self._npm_reason(ver),
                                    "severity": self._unpinned_severity_npm(ver),
                                }
                            )
            except (OSError, ValueError) as exc:
                logger.debug("supply_chain.manifest_parse_error", error=str(exc))

        for req in repo.rglob("requirements*.txt"):
            try:
                for line in req.read_text().split("\n"):
                    line = line.strip()
                    if not line or line.startswith(("#", "-")):
                        continue
                    m = re.match(r"^([A-Za-z0-9][\w.-]*)(.*)?$", line)
                    if not m:
                        continue
                    spec = (m.group(2) or "").strip()
                    if self._is_floating_py(spec):
                        findings.append(
                            {
                                "type": "unpinned",
                                "file": req.name,
                                "package": m.group(1),
                                "version": spec or "(no version)",
                                "ecosystem": "pypi",
                                "reason": self._py_reason(spec),
                                "severity": self._unpinned_severity_py(spec),
                            }
                        )
            except OSError as exc:
                logger.debug("supply_chain.requirements_read_error", file=str(req), error=str(exc))

        return findings

    def _check_lockfiles(
        self,
        files: list[str],
        repo: Path,
    ) -> list[dict]:
        findings: list[dict] = []
        changed_names = {Path(f).name for f in files}
        changed_dirs: dict[str, set[str]] = {}
        for f in files:
            p = Path(f)
            parent = str(p.parent)
            changed_dirs.setdefault(parent, set()).add(p.name)

        for lock, manifests in _LOCKFILE_TO_MANIFEST.items():
            if lock not in changed_names:
                continue
            lock_dirs = [d for d, names in changed_dirs.items() if lock in names]
            for lock_dir in lock_dirs:
                dir_files = changed_dirs.get(lock_dir, set())
                manifest_changed = any(m in dir_files for m in manifests)
            if not manifest_changed:
                findings.append(
                    {
                        "type": "lockfile",
                        "lockfile": lock,
                        "severity": "high",
                        "sha256": _sha256(Path(lock_dir) / lock),
                        "message": (f"`{lock}` changed but {'/'.join(manifests)} did NOT"),
                    }
                )

        for manifest in [
            "package.json",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
        ]:
            if manifest not in changed_names:
                continue
            expected = [lf for lf, ms in _LOCKFILE_TO_MANIFEST.items() if manifest in ms]
            manifest_dirs = [d for d, names in changed_dirs.items() if manifest in names]
            for lf in expected:
                for manifest_dir in manifest_dirs:
                    if (
                        lf not in changed_dirs.get(manifest_dir, set())
                        and (Path(manifest_dir) / lf).exists()
                    ):
                        findings.append(
                            {
                                "type": "lockfile",
                                "lockfile": lf,
                                "severity": "medium",
                                "sha256": _sha256(Path(manifest_dir) / lf),
                                "message": (f"`{manifest}` changed but `{lf}` was NOT updated"),
                            }
                        )

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_floating_npm(v: str) -> bool:
        return bool(v.startswith(("^", "~", ">=", ">")) or v in ("*", "latest", "") or " || " in v)

    @staticmethod
    def _npm_reason(v: str) -> str:
        if v.startswith("^"):
            return "caret range — allows minor+patch"
        if v.startswith("~"):
            return "tilde range — allows patch"
        if v.startswith((">=", ">")):
            return "open range — any newer version"
        if v in ("*", "latest", ""):
            return "completely unpinned"
        return "floating range"

    @staticmethod
    def _unpinned_severity_npm(v: str) -> str:
        if v in ("*", "latest", ""):
            return "critical"
        return "high"

    @staticmethod
    def _unpinned_severity_py(spec: str) -> str:
        if not spec:
            return "critical"
        return "high"

    @staticmethod
    def _is_floating_py(spec: str) -> bool:
        if not spec:
            return True
        if spec.startswith((">=", "~=")):
            return True
        return "==" in spec and "*" in spec

    @staticmethod
    def _py_reason(spec: str) -> str:
        if not spec:
            return "no version — installs latest"
        if spec.startswith(">="):
            return "minimum bound only — no upper cap"
        if spec.startswith("~="):
            return "compatible release — allows patch"
        return "floating range"

    # ── Render ────────────────────────────────────────────────────────────────

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        unpinned = [f for f in result.findings if f.get("type") == "unpinned"]
        locks = [f for f in result.findings if f.get("type") == "lockfile"]
        docker = [f for f in result.findings if f.get("type") == "docker_latest"]
        ctx["unpinned"] = unpinned
        ctx["locks"] = locks
        ctx["docker"] = docker
        ctx["unpinned_entries"] = [self._guidance_entry(f) for f in unpinned]
        ctx["lock_entries"] = [self._guidance_entry(f) for f in locks]
        ctx["docker_entries"] = [self._guidance_entry(f) for f in docker]
        return ctx

    def _render_inline(
        self,
        result: PluginResult,
    ) -> str:
        if result.error:
            return f"**supply-chain**: {result.error}"

        unpinned = [f for f in result.findings if f.get("type") == "unpinned"]
        locks = [f for f in result.findings if f.get("type") == "lockfile"]
        docker = [f for f in result.findings if f.get("type") == "docker_latest"]
        lines: list[str] = []

        if unpinned:
            lines.append("<details open>")
            lines.append(f"<summary>📌 <b>Unpinned Dependencies ({len(unpinned)})</b></summary>")
            lines.append("")
            for entry in (self._guidance_entry(f) for f in unpinned):
                lines.extend(entry["lines"])
                lines.append("")
            lines.append("</details>")
            lines.append("")

        if locks:
            lines.append("<details open>")
            lines.append("<summary>🔒 <b>Lockfile Integrity</b></summary>")
            lines.append("")
            for entry in (self._guidance_entry(f) for f in locks):
                lines.extend(entry["lines"])
                lines.append("")
            lines.append("</details>")
            lines.append("")

        if docker:
            lines.append("<details open>")
            lines.append(f"<summary>🐳 <b>Docker Floating Image Tags ({len(docker)})</b></summary>")
            lines.append("")
            for entry in (self._guidance_entry(f) for f in docker):
                lines.extend(entry["lines"])
                lines.append("")
            lines.append("</details>")
            lines.append("")

        return "\n".join(lines).rstrip()

    def _guidance_entry(self, finding: dict) -> dict[str, list[str]]:
        kind = finding.get("type")
        if kind == "unpinned":
            lines = self._unpinned_guidance_lines(finding)
        elif kind == "lockfile":
            lines = self._lockfile_guidance_lines(finding)
        elif kind == "docker_latest":
            lines = self._docker_guidance_lines(finding)
        else:
            lines = self._generic_guidance_lines(finding)
        return {"lines": lines}

    def _generic_guidance_lines(self, finding: dict) -> list[str]:
        intent = self._intent_label(finding)
        message = (
            finding.get("message") or finding.get("description") or "Supply-chain check failed."
        )
        return self._entry_lines(
            intent=intent,
            target="Supply-chain finding",
            what_failed=str(message),
            why=(
                "Supply-chain findings change what code or runtime image is installed, "
                "so they need a deterministic resolution before merge."
            ),
            fix="Update the manifest, lockfile, or image reference that produced this finding.",
            done_when="The changed dependency input and the installed dependency output agree.",
            verify=self._verify_text(),
        )

    def _unpinned_guidance_lines(self, finding: dict) -> list[str]:
        package = str(finding.get("package") or "dependency")
        manifest = str(finding.get("file") or "manifest")
        version = str(finding.get("version") or "floating range")
        ecosystem = str(finding.get("ecosystem") or "dependency manifest")
        reason = str(finding.get("reason") or "floating version range")
        severity = self._severity_evidence(finding)
        what_failed = " ".join(
            part
            for part in (
                severity,
                f"The {ecosystem} dependency uses `{version}` ({reason}).",
            )
            if part
        )
        return self._entry_lines(
            intent=self._intent_label(finding),
            target=f"`{package}` in `{manifest}`",
            what_failed=what_failed,
            why=(
                "Floating dependency ranges can resolve to different package versions in "
                "later installs, so the reviewed code and installed code can diverge."
            ),
            fix=(
                f"Pin `{package}` to an exact version and update the matching lockfile in "
                "the same change."
            ),
            done_when=(
                f"`{manifest}` uses an exact version for `{package}` and the lockfile "
                "records that exact resolution."
            ),
            verify=self._verify_text(),
        )

    def _lockfile_guidance_lines(self, finding: dict) -> list[str]:
        lockfile = str(finding.get("lockfile") or "lockfile")
        message = self._review_sentence(
            finding.get("message") or f"`{lockfile}` changed without its manifest."
        )
        evidence = self._sha_evidence(finding)
        severity = self._severity_evidence(finding)
        what_failed = " ".join(part for part in (severity, message, evidence) if part)
        return self._entry_lines(
            intent=self._intent_label(finding),
            target=f"`{lockfile}`",
            what_failed=what_failed,
            why=(
                "Manifest and lockfile drift means reviewers cannot tell which dependency "
                "set is intended to be installed."
            ),
            fix=(
                "Commit the matching manifest change, regenerate the lockfile from the "
                "intended manifest, or revert lockfile churn that does not belong here."
            ),
            done_when=(
                "The manifest and lockfile move together and describe the same dependency set."
            ),
            verify=self._verify_text(),
        )

    def _docker_guidance_lines(self, finding: dict) -> list[str]:
        file_name = Path(str(finding.get("file") or "Dockerfile")).name
        description = self._review_sentence(
            finding.get("description")
            or "Container image reference uses a floating tag or implicit latest."
        )
        severity = self._severity_evidence(finding)
        what_failed = " ".join(part for part in (severity, description) if part)
        return self._entry_lines(
            intent=self._intent_label(finding),
            target=f"`{file_name}`",
            what_failed=what_failed,
            why=(
                "Floating image tags can pull a different base image after review, changing "
                "OS packages and runtime behavior without a code diff."
            ),
            fix="Pin the image to a versioned tag or digest that the team intends to ship.",
            done_when="Each changed image reference uses a non-floating tag or digest.",
            verify=self._verify_text(),
        )

    @staticmethod
    def _intent_label(finding: dict) -> str:
        severity = str(finding.get("severity") or "").lower()
        if severity in {"critical", "high"}:
            return "Required"
        if severity in {"medium", "low"}:
            return "Consider"
        return "Consider"

    @staticmethod
    def _verify_text() -> str:
        return (
            "Rerun `uv run eedom review --repo-path . --all` and confirm this "
            "supply-chain item no longer appears."
        )

    @staticmethod
    def _sha_evidence(finding: dict) -> str:
        sha = str(finding.get("sha256") or "")
        if not sha:
            return ""
        return f"SHA256 starts with `{sha[:16]}`."

    @staticmethod
    def _severity_evidence(finding: dict) -> str:
        severity = str(finding.get("severity") or "").lower()
        if not severity:
            return ""
        return f"Severity: {severity}."

    @staticmethod
    def _review_sentence(text: object) -> str:
        sentence = " ".join(str(text).split())
        sentence = sentence.replace("DID NOT", "was not")
        if sentence and sentence[-1] not in ".!?":
            return f"{sentence}."
        return sentence

    def _entry_lines(
        self,
        *,
        intent: str,
        target: str,
        what_failed: str,
        why: str,
        fix: str,
        done_when: str,
        verify: str,
    ) -> list[str]:
        lines = [f"- **{intent}:**"]
        lines.extend(self._inline_field("Target", target))
        lines.extend(self._block_field("What failed", what_failed))
        lines.extend(self._block_field("Why it matters", why))
        lines.extend(self._block_field("Fix", fix))
        lines.extend(self._block_field("Done when", done_when))
        lines.extend(self._block_field("Verify", verify))
        return lines

    @staticmethod
    def _inline_field(label: str, text: str) -> list[str]:
        prefix = f"  {label}: "
        continuation = " " * len(prefix)
        width = max(40, 110 - len(prefix))
        wrapped = _wrap_review_text(text, width=width)
        if not wrapped:
            return []
        return [f"{prefix}{wrapped[0]}", *[f"{continuation}{line}" for line in wrapped[1:]]]

    @staticmethod
    def _block_field(label: str, text: str) -> list[str]:
        wrapped = _wrap_review_text(text)
        return [f"  {label}:", *[f"    {line}" for line in wrapped]]
