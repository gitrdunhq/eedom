"""cspell plugin — code-aware spell checking.
# tested-by: tests/unit/test_cspell_plugin.py
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin

CSPELL_DICTIONARIES: list[str] = [
    "en-CA",
    "softwareTerms",
    "python",
    "typescript",
    "node",
    "golang",
    "java",
    "rust",
    "cpp",
    "csharp",
    "html",
    "css",
    "bash",
    "docker",
    "k8s",
]


class CspellPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "cspell"

    @property
    def description(self) -> str:
        return "Code-aware spell checking (en-CA, 11 tech dictionaries)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            r = subprocess.run(
                [
                    "cspell",
                    "lint",
                    "--no-progress",
                    "--no-summary",
                    "--show-suggestions",
                    "--locale",
                    "en-CA",
                    "--dictionaries",
                    ",".join(CSPELL_DICTIONARIES),
                    "--dot",
                    *files,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "cspell"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.TIMEOUT, "cspell", timeout=0)
            )

        findings = []
        for line in (r.stdout or "").strip().split("\n"):
            if not line or " - Unknown word " not in line:
                continue
            parts = line.split(" - Unknown word ")
            if len(parts) != 2:
                continue
            loc = parts[0].strip()
            rest = parts[1].strip()
            word = rest.strip("()")
            suggestions = ""
            if " Suggestions: " in rest:
                wp, sp = rest.split(" Suggestions: ", 1)
                word = wp.strip("()")
                suggestions = sp.strip("[]")
            file_line = loc.rsplit(":", 2)
            if len(file_line) < 2:
                continue
            with contextlib.suppress(ValueError):
                findings.append(
                    {
                        "file": file_line[0],
                        "line": int(file_line[1]),
                        "word": word,
                        "suggestions": suggestions,
                    }
                )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**cspell**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>📝 <b>Spelling ({len(result.findings)})</b></summary>\n")
        lines.append("| File | Line | Word | Suggestions |")
        lines.append("|------|------|------|-------------|")
        for t in result.findings[:30]:
            lines.append(f"| `{t['file']}` | {t['line']} | `{t['word']}` | {t['suggestions']} |")
        if len(result.findings) > 30:
            lines.append(f"\n*...{len(result.findings) - 30} more*")
        lines.append("\n</details>\n")
        return "\n".join(lines)
