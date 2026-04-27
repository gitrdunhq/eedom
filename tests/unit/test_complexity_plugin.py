"""Tests for ComplexityPlugin render output capping.
# tested-by: tests/unit/test_complexity_plugin.py
"""

from __future__ import annotations

from eedom.core.plugin import PluginResult
from eedom.plugins.complexity import ComplexityPlugin


def _make_finding(name: str, ccn: int = 3, nloc: int = 10) -> dict:
    return {
        "function": name,
        "file": "src/mod.py",
        "cyclomatic_complexity": ccn,
        "maintainability_index": 85.0,
        "nloc": nloc,
    }


class TestComplexityRenderCapping:
    """Complexity render output must cap rows to prevent report truncation."""

    def test_render_caps_at_25_rows(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 25

    def test_render_shows_remaining_count(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert "15 more" in output

    def test_render_no_truncation_under_cap(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(10)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 100,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 10
        assert "more" not in output
