"""Complexity plugin — Lizard CCN + Radon MI.
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/test_complexity_plugin.py
# tested-by: tests/unit/test_plugin_templates.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.complexity_runner import run_complexity as _run

_CODE_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java", ".rs", ".c", ".cpp"}
_MAX_RENDERED_FUNCTIONS = 25
_WRAP_WIDTH = 88


def _wrap_lines(text: str, width: int = _WRAP_WIDTH) -> list[str]:
    return textwrap.wrap(
        str(text),
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]


def _complexity_guidance(ccn: int) -> str:
    if ccn > 10:
        return (
            f"CCN {ccn} means this function has enough branches to be hard to review "
            "and test confidently."
        )
    return "This function is listed for context; it is below the high-complexity threshold."


def _complexity_fix_hint(ccn: int) -> str:
    if ccn > 10:
        return (
            "Split independent branches into smaller helpers, use guard clauses where they reduce "
            "nesting, or add a short comment where the branching is intentional."
        )
    return "No required change; keep an eye on this if nearby edits add more branches."


def _ccn_int(finding: dict) -> int:
    try:
        return int(finding.get("cyclomatic_complexity", 0))
    except (TypeError, ValueError):
        return 0


def _entry_for(finding: dict) -> dict:
    ccn = _ccn_int(finding)
    mi = finding.get("maintainability_index", "?")
    nloc = finding.get("nloc", "?")
    return {
        "function": finding.get("function", "<unknown>"),
        "file": finding.get("file", "<unknown>"),
        "ccn": ccn,
        "mi": mi,
        "nloc": nloc,
        "why_lines": _wrap_lines(_complexity_guidance(ccn)),
        "consider_lines": _wrap_lines(_complexity_fix_hint(ccn)),
    }


def _complexity_context(result: PluginResult) -> dict:
    findings = result.findings[:_MAX_RENDERED_FUNCTIONS]
    high_ccn = [f for f in result.findings if _ccn_int(f) > 10]
    return {
        "entries": [_entry_for(f) for f in findings],
        "shown_count": len(findings),
        "remaining_count": max(0, len(result.findings) - _MAX_RENDERED_FUNCTIONS),
        "high_count": len(high_ccn),
        "max_rendered_functions": _MAX_RENDERED_FUNCTIONS,
    }


class ComplexityPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "complexity"

    @property
    def description(self) -> str:
        return "Cyclomatic complexity (Lizard) + maintainability index (Radon)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in _CODE_EXTS for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            data = _run(files, str(repo_path))
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        if data.get("error"):
            return PluginResult(
                plugin_name=self.name,
                error=data["error"],
            )
        return PluginResult(
            plugin_name=self.name,
            findings=data.get("functions", []),
            summary=data.get("summary", {}),
        )

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        ctx.update(_complexity_context(result))
        return ctx

    def _render_inline(
        self,
        result: PluginResult,
    ) -> str:
        if result.error:
            return f"**complexity**: {result.error}"
        if not result.findings:
            return ""
        s = result.summary
        avg = s.get("avg_cyclomatic_complexity", 0)
        mx = s.get("max_cyclomatic_complexity", 0)
        nloc = s.get("total_nloc", 0)
        ctx = _complexity_context(result)
        lines = ["<details>"]
        lines.append(
            f"<summary>📊 <b>Complexity: avg CCN {avg}, max {mx}, {nloc} NLOC</b></summary>\n"
        )
        high_note = f", {ctx['high_count']} with CCN > 10" if ctx["high_count"] else ""
        lines.append(
            f"**Top complex functions** — showing {ctx['shown_count']} of "
            f"{len(result.findings)}{high_note}.\n"
        )
        for entry in ctx["entries"]:
            lines.append(
                f"- **`{entry['function']}`** — CCN {entry['ccn']}, "
                f"MI {entry['mi']}, NLOC {entry['nloc']}"
            )
            lines.append(f"  - File: `{entry['file']}`")
            lines.append("  - Why it matters:")
            lines.extend(f"    {line}" for line in entry["why_lines"])
            lines.append("  - Consider:")
            lines.extend(f"    {line}" for line in entry["consider_lines"])
        if ctx["remaining_count"] > 0:
            lines.append(
                f"\n*...{ctx['remaining_count']} more functions; see SARIF for the full list.*"
            )
        lines.append("\n</details>\n")
        return "\n".join(lines)
