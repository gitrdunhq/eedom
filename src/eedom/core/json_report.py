# tested-by: tests/unit/test_json_report.py
"""Structured JSON output for machine consumption."""

from __future__ import annotations

from datetime import UTC, datetime

import orjson

from eedom.core.plugin import PluginResult
from eedom.core.renderer import calculate_quality_score, calculate_severity_score


def _plugin_status(result: PluginResult) -> str:
    if result.error:
        return "error"
    if result.summary.get("status") == "skipped":
        return "skipped"
    return "ran"


def render_json(
    results: list[PluginResult],
    repo: str = "",
    commit: str = "",
) -> str:
    from eedom.core.renderer import _build_sections

    verdict, _, _ = _build_sections(results, None)
    security_score = calculate_severity_score(results)
    quality_score = calculate_quality_score(results)

    total_findings = sum(len(r.findings) for r in results)

    plugins = []
    for r in results:
        status = _plugin_status(r)
        plugins.append(
            {
                "name": r.plugin_name,
                "category": r.category,
                "status": status,
                "skip_reason": r.skip_reason or None,
                "skip_remediation": r.skip_remediation or None,
                "findings_count": len(r.findings),
                "findings": r.findings,
                "summary": r.summary,
                "error": r.error or None,
            }
        )

    doc = {
        "schema_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat(),
        "repo": repo,
        "commit": commit,
        "verdict": verdict,
        "security_score": security_score,
        "quality_score": quality_score,
        "total_findings": total_findings,
        "total_plugins": len(results),
        "plugins": plugins,
    }

    return orjson.dumps(doc, option=orjson.OPT_INDENT_2).decode()
