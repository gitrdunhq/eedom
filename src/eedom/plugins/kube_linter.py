"""kube-linter plugin — K8s/Helm manifest validation.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.kube_linter_runner import run_kube_linter as _run

_REVIEW_WIDTH = 88


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


class KubeLinterPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "kube-linter"

    @property
    def description(self) -> str:
        return "K8s/Helm security — schema validation, resource limits, privileged containers"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.infra

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in (".yaml", ".yml") for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            data = _run(files, str(repo_path))
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        return PluginResult(
            plugin_name=self.name,
            findings=data.get("findings", []),
            summary={"total": data.get("finding_count", 0)},
            error=data.get("error", ""),
        )

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        ctx["entries"] = [self._guidance_entry(f) for f in result.findings[:15]]
        return ctx

    def _render_inline(self, result: PluginResult) -> str:
        if result.error:
            return f"**kube-linter**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>☸️ <b>K8s/Helm ({len(result.findings)})</b></summary>")
        lines.append("")
        for entry in (self._guidance_entry(f) for f in result.findings[:15]):
            lines.extend(entry["lines"])
            lines.append("")
        lines.append("</details>")
        return "\n".join(lines).rstrip()

    def _guidance_entry(self, finding: dict) -> dict[str, list[str]]:
        check = str(finding.get("check") or "kube-linter-check")
        kind = str(finding.get("object_kind") or "object")
        name = str(finding.get("object_name") or "resource")
        message = str(finding.get("message") or "Kubernetes manifest failed kube-linter.")
        remediation = str(finding.get("remediation") or "")
        fix = remediation or "Update the manifest so kube-linter no longer reports this check."
        if remediation:
            fix = f"💡 {fix}"
        return {
            "lines": self._entry_lines(
                target=f"`{kind}/{name}` ({check})",
                what_failed=message,
                why=(
                    "Kubernetes and Helm findings affect runtime isolation, scheduling, "
                    "or operational safety after the manifest is applied."
                ),
                fix=fix,
                done_when=f"`{kind}/{name}` satisfies `{check}` in the rendered manifest.",
                verify="Rerun kube-linter or `uv run eedom review --repo-path . --all`.",
            )
        }

    def _entry_lines(
        self,
        *,
        target: str,
        what_failed: str,
        why: str,
        fix: str,
        done_when: str,
        verify: str,
    ) -> list[str]:
        lines = ["- ☸️ **Required:**"]
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
