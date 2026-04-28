"""cspell plugin — code-aware spell checking.
# tested-by: tests/unit/test_cspell_plugin.py
"""

from __future__ import annotations

import contextlib
import re
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
        base_cmd = [
            "cspell",
            "lint",
            "--no-progress",
            "--no-summary",
            "--reporter",
            "@cspell/cspell-json-reporter",
            "--locale",
            "en-CA",
        ]

        try:
            dictionary_args = [
                arg for name in CSPELL_DICTIONARIES for arg in ("--dictionary", name)
            ]
            r = subprocess.run(
                [*base_cmd, *dictionary_args, "--dot", *files],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if (
                r.returncode != 0
                and not (r.stdout or "").strip()
                and "dictionary" in (r.stderr or "").lower()
            ):
                # Some environments do not ship optional technical dictionaries.
                # Retry with locale-only mode to preserve typo detection.
                r = subprocess.run(
                    [*base_cmd, "--dot", *files],
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
        output = r.stdout or ""
        if not output.strip() and r.stderr:
            output = r.stderr

        # Try JSON reporter output first (structured, reliable)
        import json as _json

        parsed_json = False
        with contextlib.suppress((_json.JSONDecodeError, KeyError, TypeError)):
            data = _json.loads(output)
            for issue in data.get("issues", []):
                findings.append(
                    {
                        "file": issue.get("uri", issue.get("filePath", "")),
                        "line": issue.get("row", issue.get("line", 0)),
                        "word": issue.get("text", ""),
                        "suggestions": ", ".join(issue.get("suggestions", [])),
                    }
                )
            parsed_json = True

        # Fallback: regex parse for legacy text output
        if not parsed_json:
            pattern = re.compile(
                r"^(?P<file>.+?):(?P<line>\d+)(?::\d+)?\s*-?\s*Unknown word\s*"
                r"\((?P<word>[^)]+)\)(?:\s+Suggestions:\s+\[(?P<suggestions>[^\]]*)\])?"
            )
            for line in output.strip().split("\n"):
                if not line:
                    continue
                match = pattern.match(line.strip())
                if not match:
                    continue
                with contextlib.suppress(ValueError):
                    findings.append(
                        {
                            "file": match.group("file"),
                            "line": int(match.group("line")),
                            "word": match.group("word"),
                            "suggestions": match.group("suggestions") or "",
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
