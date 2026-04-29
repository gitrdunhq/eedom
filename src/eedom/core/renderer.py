"""Comment renderer — assembles plugin results into markdown.
# tested-by: tests/unit/test_renderer.py

Pure function: no I/O beyond reading template files.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import jinja2

from eedom.core.plugin import PluginResult
from eedom.core.version import get_version

_MAX_COMMENT_LENGTH = 65536

CATEGORY_PRIORITY: dict[str, int] = {
    "supply_chain": 0,
    "dependency": 1,
    "infra": 2,
    "code": 3,
    "quality": 4,
}
_DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_VERSION = get_version()

_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_SECURITY_PLUGINS: set[str] = {
    "gitleaks",
    "semgrep",
    "trivy",
    "osv-scanner",
    "clamav",
    "supply-chain",
    "opa",
    "scancode",
    "kube-linter",
    "mypy",
}

_QUALITY_PLUGINS: set[str] = {
    "blast-radius",
    "complexity",
    "cpd",
    "cspell",
    "ls-lint",
}


def _plugin_is_security(plugin_name: str) -> bool:
    normalized = plugin_name.lower().replace("_", "-")
    return normalized in _SECURITY_PLUGINS


def _collapse_excess_blank_lines(output: str) -> str:
    while "\n\n\n" in output:
        output = output.replace("\n\n\n", "\n\n")
    return output


def _compact_smart_spacing(output: str) -> str:
    labels = {
        "- What failed:",
        "- Why it blocks:",
        "- Fix:",
        "- Done when:",
        "- Verify:",
    }
    lines = output.splitlines()
    compacted: list[str] = []
    for index, line in enumerate(lines):
        previous = compacted[-1] if compacted else ""
        next_line = lines[index + 1] if index + 1 < len(lines) else ""
        if (
            line == ""
            and next_line.startswith("  ")
            and (previous in labels or previous.startswith("  "))
        ):
            continue
        compacted.append(line)
    return "\n".join(compacted) + ("\n" if output.endswith("\n") else "")


def _wrap_lines(text: str, width: int = 96) -> list[str]:
    return textwrap.wrap(
        str(text),
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]


def _finding_severity(finding: dict) -> str:
    return str(finding.get("severity", "")).lower()


def _finding_label(finding: dict) -> str:
    rule = (
        finding.get("rule") or finding.get("rule_id") or finding.get("id") or finding.get("check")
    )
    if rule:
        return str(rule)
    return "finding"


def _finding_target(finding: dict) -> str:
    file_path = finding.get("file") or finding.get("path")
    line = finding.get("line") or finding.get("start_line")
    if file_path:
        return f"`{file_path}:{line}`" if line else f"`{file_path}`"
    package = finding.get("package")
    if package:
        version = finding.get("version")
        return f"`{package}@{version}`" if version else f"`{package}`"
    return f"`{_finding_label(finding)}`"


def _finding_message(finding: dict) -> str:
    return str(
        finding.get("message")
        or finding.get("description")
        or finding.get("summary")
        or _finding_label(finding)
    )


def _remediation_for(plugin_name: str, finding: dict) -> str:
    fixed_version = str(finding.get("fixed_version", "")).strip()
    package = finding.get("package")
    version = finding.get("version")
    if fixed_version and package:
        current = f" from `{version}`" if version else ""
        return f"Upgrade `{package}`{current} to `{fixed_version}`."

    label = _finding_label(finding).lower()
    message = _finding_message(finding).lower()
    if plugin_name == "gitleaks" or "secret" in label or "secret" in message or "key" in label:
        return (
            "Remove or rotate the secret, move it to the configured secret store, "
            "and invalidate the exposed credential."
        )
    if plugin_name in {"trivy", "osv", "osv-scanner"} or package:
        return (
            "Replace the dependency, pin a safe alternative, or document an accepted risk "
            "until upstream publishes a fixed release."
        )
    if plugin_name in {"kube-linter", "cdk-nag", "cfn-nag", "opa"}:
        return "Update the affected manifest or policy input so this rule no longer matches."
    return (
        "Simplify the flagged code/config where possible, or make the intent explicit, "
        "then change it so this rule no longer matches."
    )


def _blocking_results(results: list[PluginResult]) -> list[PluginResult]:
    blockers = []
    for result in results:
        if result.category not in {"dependency", "supply_chain", "infra"}:
            continue
        if any(_finding_severity(f) in {"critical", "high"} for f in result.findings):
            blockers.append(result)
    return blockers


def _build_block_reason(results: list[PluginResult]) -> str:
    blockers = _blocking_results(results)
    if not blockers:
        return ""

    parts = []
    total = 0
    for result in blockers[:3]:
        count = sum(1 for f in result.findings if _finding_severity(f) in {"critical", "high"})
        total += count
        parts.append(f"{count} from {result.plugin_name}")
    for result in blockers[3:]:
        total += sum(1 for f in result.findings if _finding_severity(f) in {"critical", "high"})
    suffix = "" if len(blockers) <= 3 else f" (+{len(blockers) - 3} more sources)"
    noun = "finding" if total == 1 else "findings"
    return (
        f"Why blocked: {total} critical/high security {noun} ("
        + ", ".join(parts)
        + suffix
        + ") must be fixed before merge."
    )


def _relevance_for(result: PluginResult, finding: dict) -> str:
    label = _finding_label(finding).lower()
    message = _finding_message(finding).lower()
    if result.plugin_name == "gitleaks" or "secret" in label or "secret" in message:
        return "Exposed credentials remain reusable outside this PR until removed and rotated."
    if result.category == "dependency":
        return "A vulnerable dependency can ship exploitable code with the application."
    if result.category == "infra":
        return "Unsafe infrastructure config can change deployed runtime security."
    return f"{result.category} findings can ship security risk if merged."


def _build_smart_plan(results: list[PluginResult]) -> list[dict[str, object]]:
    plan: list[dict[str, object]] = []
    for result in _blocking_results(results):
        blocking_findings = [
            f for f in result.findings if _finding_severity(f) in {"critical", "high"}
        ]
        if not blocking_findings:
            continue
        first = blocking_findings[0]
        target = _finding_target(first)
        label = _finding_label(first)
        severity = _finding_severity(first).upper()
        fields = [
            {
                "label": "What failed",
                "lines": _wrap_lines(
                    f"{result.plugin_name} reported {severity} `{label}` at {target}: "
                    f"{_finding_message(first)}"
                ),
            },
            {
                "label": "Why it blocks",
                "lines": _wrap_lines(_relevance_for(result, first)),
            },
            {
                "label": "Fix",
                "lines": _wrap_lines(_remediation_for(result.plugin_name, first)),
            },
            {
                "label": "Done when",
                "lines": _wrap_lines(
                    f"{result.plugin_name} critical/high findings drop from "
                    f"{len(blocking_findings)} to 0."
                ),
            },
            {
                "label": "Verify",
                "lines": _wrap_lines(
                    f"Rerun `uv run eedom review --repo-path . --all` after fixing {target}."
                ),
            },
        ]
        plan.append(
            {
                "label": "Required",
                "source": result.plugin_name,
                "count": len(blocking_findings),
                "fields": fields,
            }
        )
    return plan


def calculate_severity_score(results: list[PluginResult]) -> float:
    """Return a 0-100 health score based on security plugin findings only.

    Quality plugins (blast-radius, complexity, cpd, cspell, ls-lint) are
    excluded from the score — they are advisory, not merge-blocking.

    Formula: max(0, 100 - sum(weight(severity) for each security finding))
    Weights: critical=10, high=5, medium=2, low=1, info=0.
    """
    total_weight = 0
    for result in results:
        if not _plugin_is_security(result.plugin_name):
            continue
        for finding in result.findings:
            sev = str(finding.get("severity", "")).lower()
            total_weight += _SEVERITY_WEIGHTS.get(sev, 0)
    return max(0.0, min(100.0, 100.0 - total_weight))


def calculate_quality_score(results: list[PluginResult]) -> float:
    """Return a 0-100 quality score based on quality plugin findings only.

    Advisory — does not gate merges. Reported alongside the security score.
    """
    total_weight = 0
    for result in results:
        if _plugin_is_security(result.plugin_name):
            continue
        for finding in result.findings:
            sev = str(finding.get("severity", "")).lower()
            total_weight += _SEVERITY_WEIGHTS.get(sev, 0)
    return max(0.0, min(100.0, 100.0 - total_weight))


def _is_monorepo(results: list[PluginResult]) -> bool:
    """Return True when at least one result carries a package_root label."""
    return any(r.package_root is not None for r in results)


def _group_by_package(results: list[PluginResult]) -> dict[str, list[PluginResult]]:
    """Partition results by package_root, preserving insertion order."""
    packages: dict[str, list[PluginResult]] = {}
    for r in results:
        key = r.package_root or ""
        packages.setdefault(key, []).append(r)
    return packages


def _verdict_rank(verdict: str) -> int:
    return {"blocked": 3, "warnings": 2, "incomplete": 1, "clear": 0}.get(verdict, 0)


def _build_monorepo_sections(
    results: list[PluginResult],
    plugin_renderers: dict[str, object] | None,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    """Build per-package sections for monorepo results.

    Returns the same (verdict, summary_rows, sections) triple as
    _build_sections so render_comment can use either path transparently.
    """
    packages = _group_by_package(results)
    overall_verdict = "clear"
    summary_rows: list[tuple[str, str]] = []
    sections: list[str] = []

    for pkg_root, pkg_results in packages.items():
        pkg_verdict, pkg_rows, pkg_finding_sections = _build_sections(pkg_results, plugin_renderers)
        pkg_score = calculate_severity_score(pkg_results)
        pkg_quality = calculate_quality_score(pkg_results)

        if _verdict_rank(pkg_verdict) > _verdict_rank(overall_verdict):
            overall_verdict = pkg_verdict

        header = pkg_root if pkg_root else "(root)"
        pkg_lines: list[str] = [
            f"## {header}",
            f"> Security: {int(pkg_score)}/100 · Quality: {int(pkg_quality)}/100",
            "",
            "| Plugin | Findings |",
            "|--------|----------|",
        ]
        for row in pkg_rows:
            pkg_lines.append(f"| {row[0]} | {row[1]} |")

        for fs in pkg_finding_sections:
            if fs:
                pkg_lines.append("")
                pkg_lines.append(fs)

        sections.append("\n".join(pkg_lines))
        summary_rows.append(
            (
                header,
                f"{pkg_verdict.upper()} (Sec: {int(pkg_score)} · Qual: {int(pkg_quality)})",
            )
        )

    return overall_verdict, summary_rows, sections


def render_comment(
    results: list[PluginResult],
    repo: str = "",
    pr_num: int = 0,
    title: str = "",
    file_count: int = 0,
    template_dir: Path | None = None,
    plugin_renderers: dict[str, object] | None = None,
) -> str:
    tpl_dir = template_dir or _DEFAULT_TEMPLATE_DIR
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(tpl_dir)),
        autoescape=False,  # nosemgrep: jinja2-autoescape-disabled — output is markdown, not HTML
        keep_trailing_newline=True,
    )
    template = env.get_template("comment.md.j2")

    if _is_monorepo(results):
        verdict, summary_rows, sections = _build_monorepo_sections(results, plugin_renderers)
    else:
        verdict, summary_rows, sections = _build_sections(results, plugin_renderers)

    severity_score = calculate_severity_score(results)
    quality_score = calculate_quality_score(results)
    mi_grade, mi_score, mi_icon, avg_ccn, hi_ccn, mi_c_count = _extract_mi(results)

    from eedom.core.actionability import classify_findings

    act_summary = classify_findings(results)
    smart_plan = _build_smart_plan(results)
    block_reason = _build_block_reason(results)

    footer_parts = []
    for r in results:
        if r.error:
            continue
        count = len(r.findings)
        if count:
            footer_parts.append(f"{count} {r.plugin_name}")
    footer_stats = " · ".join(footer_parts) if footer_parts else "clean"

    output = template.render(
        repo=repo,
        pr_num=pr_num,
        title=title,
        verdict=verdict,
        file_count=file_count,
        summary_rows=summary_rows,
        sections=sections,
        severity_score=severity_score,
        quality_score=quality_score,
        mi_grade=mi_grade,
        mi_score=mi_score,
        mi_icon=mi_icon,
        avg_ccn=avg_ccn,
        hi_ccn=hi_ccn,
        mi_c_count=mi_c_count,
        version=_VERSION,
        footer_stats=footer_stats,
        actionability=act_summary,
        smart_plan=smart_plan,
        block_reason=block_reason,
    )
    output = _collapse_excess_blank_lines(output)
    output = _compact_smart_spacing(output)

    if len(output) > _MAX_COMMENT_LENGTH:
        truncated = output[: _MAX_COMMENT_LENGTH - 100]
        truncated += "\n\n*[comment truncated — full report in artifacts]*"
        return truncated

    return output


def _build_sections(
    results: list[PluginResult],
    plugin_renderers: dict[str, object] | None,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    verdict = "clear"
    summary_rows: list[tuple[str, str]] = []
    sections: list[str] = []

    _max_priority = max(CATEGORY_PRIORITY.values()) + 1
    sorted_results = sorted(
        results,
        key=lambda r: CATEGORY_PRIORITY.get(r.category, _max_priority),
    )

    for r in sorted_results:
        count = len(r.findings)
        label = r.plugin_name

        if r.error:
            summary_rows.append((label, f"error: {r.error}"))
            if verdict == "clear":
                verdict = "incomplete"
            continue

        status = r.summary.get("status", "")
        if status == "skipped":
            summary_rows.append((label, "skipped"))
            continue

        summary_rows.append((label, str(count)))

        has_crit = any(f.get("severity") in ("critical", "high") for f in r.findings)
        is_security = r.category in {"dependency", "supply_chain", "infra"}
        if has_crit and is_security:
            verdict = "blocked"
        elif count and verdict != "blocked":
            verdict = "warnings"

        renderer = None
        if plugin_renderers:
            renderer = plugin_renderers.get(r.plugin_name)

        if renderer is not None and callable(getattr(renderer, "render", None)):
            try:
                md = renderer.render(r)
            except Exception:  # noqa: BLE001
                md = _default_render(r)
        else:
            md = _default_render(r)

        if md:
            sections.append(md)

    return verdict, summary_rows, sections


def _default_render(result: PluginResult) -> str:
    if not result.findings:
        return ""
    count = len(result.findings)
    noun = "finding" if count == 1 else "findings"
    lines = [f"**{result.plugin_name}**: {count} {noun}"]
    return "\n".join(lines)


class MarkdownRenderer:
    """ReportRendererPort implementation that produces a markdown PR comment."""

    def render(self, report) -> str:  # report: ReviewReport
        return render_comment(report.plugin_results)


def _extract_mi(
    results: list[PluginResult],
) -> tuple[str, int, str, float, int, int]:
    for r in results:
        if r.plugin_name == "complexity" and r.findings:
            s = r.summary
            avg = s.get("avg_cyclomatic_complexity", 0)
            mi_scores = []
            for f in r.findings:
                mi_str = f.get("maintainability_index", "")
                if "(" in str(mi_str):
                    try:
                        val = float(str(mi_str).split("(")[1].rstrip(")"))
                        mi_scores.append(val)
                    except (ValueError, IndexError):
                        pass
            avg_mi = sum(mi_scores) / len(mi_scores) if mi_scores else 0
            grade = "A" if avg_mi >= 20 else ("B" if avg_mi >= 10 else "C")
            icon = {"A": "🟢", "B": "🟡", "C": "🔴"}.get(grade, "⚪")
            hi = s.get("high_complexity_count", 0)
            c_count = sum(1 for s in mi_scores if s < 10)
            return grade, int(avg_mi), icon, avg, hi, c_count
    return "", 0, "", 0.0, 0, 0
