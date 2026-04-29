"""Semgrep plugin — AST-based code pattern matching.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.semgrep_runner import run_semgrep as _run

_REVIEW_WIDTH = 88

_CODE_EXTS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".rb",
    ".java",
    ".rs",
    ".sh",
    ".tf",
    ".hcl",
    ".yaml",
    ".yml",
}


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


class SemgrepPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def description(self) -> str:
        return "Code pattern analysis — AST matching via opengrep (local rules only)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in _CODE_EXTS for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            data = _run(files, str(repo_path), timeout=120)
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        if data.get("status") == "error":
            errors = data.get("errors", [])
            msg = errors[0]["message"] if errors else "unknown error"
            return PluginResult(
                plugin_name=self.name,
                error=f"scanner degraded: {msg}",
            )

        findings = []
        for r in data.get("results", []):
            raw_path = r.get("path", "?")
            try:
                rel_path = str(Path(raw_path).relative_to(repo_path))
            except ValueError:
                rel_path = raw_path
            findings.append(
                {
                    "rule_id": r.get("check_id", "?"),
                    "file": rel_path,
                    "start_line": r.get("start", {}).get("line", 0),
                    "end_line": r.get("end", {}).get("line", 0),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "message": r.get("extra", {}).get("message", ""),
                }
            )
        findings.sort(key=lambda f: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(f["severity"], 3))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        ctx["entries"] = [self._guidance_entry(f) for f in result.findings]
        return ctx

    def _render_inline(self, result: PluginResult) -> str:
        if result.error:
            return f"**semgrep**: {result.error}"
        if not result.findings:
            return ""
        lines = [
            "<details open>",
            f"<summary>🔍 <b>Semgrep ({len(result.findings)})</b></summary>",
            "",
        ]
        for entry in (self._guidance_entry(f) for f in result.findings):
            lines.extend(entry["lines"])
            lines.append("")
        lines.append("</details>")
        return "\n".join(lines).rstrip()

    def _guidance_entry(self, finding: dict) -> dict[str, list[str]]:
        severity = str(finding.get("severity") or "WARNING").upper()
        icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(severity, "•")
        intent = {"ERROR": "Required", "WARNING": "Consider", "INFO": "FYI"}.get(
            severity, "Consider"
        )
        rule_id = str(finding.get("rule_id") or "?")
        rule = rule_id.split(".")[-1]
        file = str(finding.get("file") or "?")
        line = finding.get("start_line") or 0
        message = str(finding.get("message") or "Semgrep matched this code pattern.")
        return {
            "lines": self._entry_lines(
                icon=icon,
                intent=intent,
                target=f"`{file}:{line}` ({rule})",
                what_failed=f"{message} Rule: `{rule_id}`.",
                why=self._why_text(rule_id, message),
                fix=self._fix_text(rule_id, message),
                done_when=(
                    f"`{file}:{line}` no longer matches `{rule_id}`, or the suppression "
                    "is justified."
                ),
                verify="Rerun Semgrep or `uv run eedom review --repo-path . --all`.",
            )
        }

    @staticmethod
    def _why_text(rule_id: str, message: str) -> str:
        lowered = f"{rule_id} {message}".lower()
        if "sql" in lowered:
            return (
                "SQL construction in changed code can let input alter the query shape, "
                "which turns reviewable data flow into an injection risk."
            )
        if "hash" in lowered or "md5" in lowered:
            return (
                "Weak hashes are not suitable for security-sensitive data because attackers "
                "can brute-force or collide them more easily."
            )
        return (
            "Semgrep matched a code pattern that reviewers should not have to infer from "
            "scanner output alone."
        )

    @staticmethod
    def _fix_text(rule_id: str, message: str) -> str:
        lowered = f"{rule_id} {message}".lower()
        if "sql" in lowered:
            return "Use parameterized queries or the framework query builder for this path."
        if "hash" in lowered or "md5" in lowered:
            return "Use an approved password hashing or digest primitive for this use case."
        return (
            "Change the code so the rule no longer matches, or add a narrow suppression "
            "with justification if this is a false positive."
        )

    def _entry_lines(
        self,
        *,
        icon: str,
        intent: str,
        target: str,
        what_failed: str,
        why: str,
        fix: str,
        done_when: str,
        verify: str,
    ) -> list[str]:
        lines = [f"- {icon} **{intent}:**"]
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
