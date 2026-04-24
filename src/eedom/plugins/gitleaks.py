"""Gitleaks plugin — secret and credential detection.
# tested-by: tests/unit/test_gitleaks_plugin.py

Wraps gitleaks CLI. Exit 0 = clean, 1 = leaks found.
Secrets are NEVER included in findings — only rule ID, file, and line.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
)

logger = structlog.get_logger(__name__)


class GitleaksPlugin(ScannerPlugin):
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
        try:
            r = subprocess.run(
                [
                    "gitleaks",
                    "dir",
                    str(repo_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    "/dev/stdout",
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "gitleaks"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(
                    ErrorCode.TIMEOUT,
                    "gitleaks",
                    timeout=timeout,
                ),
            )

        if not r.stdout or r.stdout.strip() == "[]":
            return PluginResult(
                plugin_name=self.name,
                summary={"leaks": 0},
            )

        try:
            raw = json.loads(r.stdout)
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
