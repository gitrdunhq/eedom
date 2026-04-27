"""Trivy plugin — vulnerability scanning.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class TrivyPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "trivy"

    @property
    def description(self) -> str:
        return "Vulnerability scanning (Trivy database)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            r = subprocess.run(
                ["trivy", "fs", "--format", "json", "--scanners", "vuln", str(repo_path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "trivy")
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.TIMEOUT, "trivy", timeout=0)
            )

        try:
            data = json.loads(r.stdout) if r.stdout else {}
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.PARSE_ERROR, "trivy")
            )

        findings = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "id": vuln.get("VulnerabilityID", "?"),
                        "url": vuln.get("PrimaryURL", ""),
                        "summary": vuln.get("Title") or vuln.get("Description", "")[:100],
                        "severity": _SEV_MAP.get(vuln.get("Severity", ""), "info"),
                        "package": vuln.get("PkgName", "?"),
                        "version": vuln.get("InstalledVersion", "?"),
                        "fixed_version": vuln.get("FixedVersion", ""),
                    }
                )

        crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings), "critical_high": crit},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**trivy**: {result.error}"
        if not result.findings:
            return ""
        return f"Trivy: {len(result.findings)} vulnerabilities found"
