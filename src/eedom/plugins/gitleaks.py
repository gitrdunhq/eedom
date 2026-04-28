"""Gitleaks plugin — secret and credential detection.
# tested-by: tests/unit/test_gitleaks_plugin.py

Wraps gitleaks CLI. Exit 0 = clean, 1 = leaks found.
Secrets are NEVER included in findings — only rule ID, file, and line.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
)
from eedom.core.subprocess_runner import SubprocessToolRunner
from eedom.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)


class GitleaksPlugin(ScannerPlugin):
    def __init__(self, tool_runner: ToolRunnerPort | None = None) -> None:
        self._runner: ToolRunnerPort = (
            tool_runner if tool_runner is not None else SubprocessToolRunner()
        )

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def description(self) -> str:
        return "Secret and credential detection (800+ patterns)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 60,
    ) -> PluginResult:
        cmd = [
            "gitleaks",
            "dir",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--no-banner",
        ]
        custom_config = repo_path / ".eedom" / "gitleaks.toml"
        if custom_config.is_file():
            cmd.extend(["--config", str(custom_config)])
            logger.info("gitleaks.custom_config", path=str(custom_config))

        result = self._runner.run(ToolInvocation(cmd=cmd, cwd=str(repo_path), timeout=timeout))

        if result.not_installed:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "gitleaks"),
            )
        if result.timed_out:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "gitleaks", timeout=timeout),
            )

        if not result.stdout or result.stdout.strip() == "[]":
            return PluginResult(
                plugin_name=self.name,
                summary={"leaks": 0},
            )

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.PARSE_ERROR, "gitleaks"),
            )

        findings = []
        for leak in raw:
            findings.append(
                {
                    "rule": leak.get("RuleID", "?"),
                    "description": leak.get("Description", ""),
                    "file": leak.get("File", "?"),
                    "line": leak.get("StartLine", 0),
                    "entropy": leak.get("Entropy", 0),
                    "fingerprint": leak.get("Fingerprint", ""),
                    "severity": "critical",
                    "category": "secret",
                }
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"leaks": len(findings)},
        )

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**gitleaks**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>🔑 <b>Secrets Detected ({len(result.findings)})</b></summary>\n")
        lines.append("| File | Line | Rule | Description |")
        lines.append("|------|------|------|-------------|")
        for f in result.findings:
            lines.append(f"| `{f['file']}` | {f['line']} | `{f['rule']}` | {f['description']} |")
        lines.append("\n</details>\n")
        return "\n".join(lines)
