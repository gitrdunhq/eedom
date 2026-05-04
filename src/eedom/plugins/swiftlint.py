"""SwiftLint plugin — Swift style and code smell detection.
# tested-by: tests/unit/test_swiftlint_plugin.py

Wraps the SwiftLint CLI. Exit 0 = clean, 1 = violations found (normal).
Custom rules bundled in policies/swiftlint/default.yml cover project-specific
patterns (NSLock, unchecked Sendable, print, NotificationCenter, etc.).
Per-repo overrides: .eedom/swiftlint.yml takes precedence over the bundled config.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.core.subprocess_runner import SubprocessToolRunner
from eedom.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)

_SWIFT_EXT = ".swift"

_BUNDLED_CONFIG = (
    Path(__file__).parent.parent.parent.parent / "policies" / "swiftlint" / "default.yml"
)

_SEV_MAP = {
    "error": "error",
    "warning": "warning",
    "info": "info",
}


def _resolve_config(repo_path: Path) -> Path:
    custom = repo_path / ".eedom" / "swiftlint.yml"
    if custom.is_file():
        logger.info("swiftlint.custom_config", path=str(custom))
        return custom
    return _BUNDLED_CONFIG


def _make_relative(file_path: str, repo_path: Path) -> str:
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        return file_path


class SwiftLintPlugin(ScannerPlugin):
    def __init__(self, tool_runner: ToolRunnerPort | None = None) -> None:
        self._runner: ToolRunnerPort = (
            tool_runner if tool_runner is not None else SubprocessToolRunner()
        )

    @property
    def name(self) -> str:
        return "swiftlint"

    @property
    def description(self) -> str:
        return "Swift style and code smell detection (200+ rules + project custom rules)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix == _SWIFT_EXT for f in files)

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 60,
    ) -> PluginResult:
        swift_files = [f for f in files if Path(f).suffix == _SWIFT_EXT]
        if not swift_files:
            return PluginResult(plugin_name=self.name, skip_reason="no Swift files")

        config = _resolve_config(repo_path)
        cmd = [
            "swiftlint",
            "lint",
            "--reporter",
            "json",
            "--quiet",
            "--config",
            str(config),
            *swift_files,
        ]

        result = self._runner.run(ToolInvocation(cmd=cmd, cwd=str(repo_path), timeout=timeout))

        if result.not_installed:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "swiftlint"),
            )
        if result.timed_out:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "swiftlint", timeout=timeout),
            )
        # swiftlint: 0=clean, 1=violations found, 2=error
        if result.exit_code == 2:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.BINARY_CRASHED, "swiftlint", exit_code=result.exit_code),
            )

        if not result.stdout or not result.stdout.strip():
            return PluginResult(plugin_name=self.name, summary={"violations": 0})

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.PARSE_ERROR, "swiftlint"),
            )

        findings = []
        for item in raw:
            sev_raw = item.get("severity", "Warning").lower()
            severity = _SEV_MAP.get(sev_raw, "warning")
            findings.append(
                {
                    "rule_id": item.get("rule_id", ""),
                    "message": item.get("reason", ""),
                    "file": _make_relative(item.get("file", ""), repo_path),
                    "line": item.get("line", 0),
                    "character": item.get("character", 0),
                    "severity": severity,
                    "category": "code-smell",
                    "url": item.get("url", ""),
                }
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"violations": len(findings)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**swiftlint**: {result.error}"
        if not result.findings:
            return ""

        errors = [f for f in result.findings if f.get("severity") == "error"]
        warnings = [f for f in result.findings if f.get("severity") == "warning"]
        total = len(result.findings)

        lines = ["<details>"]
        lines.append(
            f"<summary>🦅 <b>SwiftLint ({total} violation{'s' if total != 1 else ''})</b>"
            f" — {len(errors)} error{'s' if len(errors) != 1 else ''}"
            f", {len(warnings)} warning{'s' if len(warnings) != 1 else ''}</summary>\n"
        )
        lines.append("| File | Line | Rule | Severity | Message |")
        lines.append("|------|------|------|----------|---------|")

        for f in sorted(
            result.findings,
            key=lambda x: (x.get("severity", ""), x.get("file", ""), x.get("line", 0)),
        ):
            sev_icon = "🔴" if f.get("severity") == "error" else "🟡"
            rule = f.get("rule_id", "")
            url = f.get("url", "")
            rule_display = f"[`{rule}`]({url})" if url else f"`{rule}`"
            lines.append(
                f"| `{f.get('file', '')}` | {f.get('line', '')} "
                f"| {rule_display} | {sev_icon} {f.get('severity', '')} "
                f"| {f.get('message', '')} |"
            )

        lines.append("\n</details>\n")
        return "\n".join(lines)
