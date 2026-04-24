"""Tests for SARIF v2.1.0 output format.
# tested-by: tests/unit/test_sarif.py
"""

from __future__ import annotations

import json

import pytest

from eedom.core.plugin import PluginResult
from eedom.core.sarif import to_sarif

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)


class TestEmptyResults:
    """to_sarif with no plugin results produces a valid skeleton."""

    def test_version_and_schema(self) -> None:
        out = to_sarif([])
        assert out["version"] == "2.1.0"
        assert out["$schema"] == _SARIF_SCHEMA

    def test_runs_is_empty_list(self) -> None:
        out = to_sarif([])
        assert out["runs"] == []

    def test_valid_json_serialisable(self) -> None:
        out = to_sarif([])
        serialised = json.dumps(out)
        reloaded = json.loads(serialised)
        assert reloaded["version"] == "2.1.0"


class TestSinglePluginWithFindings:
    """Single plugin with two findings produces one SARIF run."""

    def _make_result(self) -> PluginResult:
        return PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2",
                    "file": "src/app.py",
                    "start_line": 42,
                    "severity": "ERROR",
                    "message": "Direct use of Jinja2 is dangerous",
                },
                {
                    "rule_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "file": "src/utils.py",
                    "start_line": 10,
                    "severity": "WARNING",
                    "message": "Use of eval is dangerous",
                },
            ],
            summary={"total": 2},
        )

    def test_produces_one_run(self) -> None:
        out = to_sarif([self._make_result()])
        assert len(out["runs"]) == 1

    def test_tool_driver_name(self) -> None:
        out = to_sarif([self._make_result()])
        assert out["runs"][0]["tool"]["driver"]["name"] == "semgrep"

    def test_results_count(self) -> None:
        out = to_sarif([self._make_result()])
        assert len(out["runs"][0]["results"]) == 2

    def test_rule_id_populated(self) -> None:
        out = to_sarif([self._make_result()])
        rule_ids = {r["ruleId"] for r in out["runs"][0]["results"]}
        assert (
            "python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2" in rule_ids
        )

    def test_message_text_populated(self) -> None:
        out = to_sarif([self._make_result()])
        messages = {r["message"]["text"] for r in out["runs"][0]["results"]}
        assert "Direct use of Jinja2 is dangerous" in messages

    def test_location_file_and_line(self) -> None:
        out = to_sarif([self._make_result()])
        first = out["runs"][0]["results"][0]
        loc = first["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/app.py"
        assert loc["region"]["startLine"] == 42


class TestSeverityMapping:
    """Severity fields are mapped correctly to SARIF levels."""

    @pytest.mark.parametrize(
        "severity,expected_level",
        [
            ("critical", "error"),
            ("CRITICAL", "error"),
            ("high", "error"),
            ("HIGH", "error"),
            ("ERROR", "error"),
            ("medium", "warning"),
            ("MEDIUM", "warning"),
            ("WARNING", "warning"),
            ("MODERATE", "warning"),
            ("low", "note"),
            ("LOW", "note"),
            ("info", "note"),
            ("INFO", "note"),
            ("note", "note"),
            ("NOTE", "note"),
            ("unknown_value", "note"),  # safe default
        ],
    )
    def test_level_mapping(self, severity: str, expected_level: str) -> None:
        result = PluginResult(
            plugin_name="test-plugin",
            findings=[
                {
                    "rule_id": "test-rule",
                    "severity": severity,
                    "message": "test message",
                }
            ],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["level"] == expected_level


class TestMultiplePlugins:
    """Multiple plugins produce multiple SARIF runs."""

    def test_two_plugins_two_runs(self) -> None:
        results = [
            PluginResult(
                plugin_name="semgrep",
                findings=[
                    {
                        "rule_id": "python.rule",
                        "severity": "ERROR",
                        "message": "semgrep finding",
                    }
                ],
                summary={},
            ),
            PluginResult(
                plugin_name="osv-scanner",
                findings=[
                    {
                        "id": "CVE-2023-0001",
                        "severity": "high",
                        "package": "requests",
                        "version": "2.0.0",
                        "summary": "Known vulnerability in requests",
                    }
                ],
                summary={},
            ),
        ]
        out = to_sarif(results)
        assert len(out["runs"]) == 2

    def test_run_names_match_plugins(self) -> None:
        results = [
            PluginResult(plugin_name="semgrep", findings=[], summary={}),
            PluginResult(plugin_name="gitleaks", findings=[], summary={}),
        ]
        out = to_sarif(results)
        names = [run["tool"]["driver"]["name"] for run in out["runs"]]
        assert names == ["semgrep", "gitleaks"]

    def test_error_plugins_still_produce_runs(self) -> None:
        """Errored plugins still appear as runs with zero results."""
        results = [
            PluginResult(plugin_name="semgrep", findings=[], summary={}, error="timeout"),
        ]
        out = to_sarif(results)
        assert len(out["runs"]) == 1
        assert out["runs"][0]["results"] == []


class TestRuleIdFallbacks:
    """Various finding shapes map to a ruleId without raising."""

    def test_advisory_id_key(self) -> None:
        result = PluginResult(
            plugin_name="osv-scanner",
            findings=[
                {
                    "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                    "severity": "high",
                    "summary": "Advisory finding",
                }
            ],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["ruleId"] == "GHSA-xxxx-yyyy-zzzz"

    def test_id_key_fallback(self) -> None:
        result = PluginResult(
            plugin_name="osv-scanner",
            findings=[
                {
                    "id": "CVE-2023-0286",
                    "severity": "high",
                    "summary": "CVE finding",
                }
            ],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["ruleId"] == "CVE-2023-0286"

    def test_missing_id_falls_back_to_plugin_name(self) -> None:
        result = PluginResult(
            plugin_name="clamav",
            findings=[
                {
                    "file": "malware.zip",
                    "severity": "critical",
                    "description": "malware detected",
                }
            ],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["ruleId"] == "clamav"


class TestMessageFallbacks:
    """Various finding shapes map to message.text without raising."""

    def test_message_key(self) -> None:
        result = PluginResult(
            plugin_name="semgrep",
            findings=[{"rule_id": "r", "severity": "ERROR", "message": "msg from message"}],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["message"]["text"] == "msg from message"

    def test_description_key(self) -> None:
        result = PluginResult(
            plugin_name="clamav",
            findings=[{"rule_id": "r", "severity": "critical", "description": "desc text"}],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["message"]["text"] == "desc text"

    def test_summary_key(self) -> None:
        result = PluginResult(
            plugin_name="osv-scanner",
            findings=[{"id": "CVE-2023-1", "severity": "high", "summary": "summary text"}],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["results"][0]["message"]["text"] == "summary text"

    def test_empty_message_is_string(self) -> None:
        result = PluginResult(
            plugin_name="clamav",
            findings=[{"severity": "low"}],
            summary={},
        )
        out = to_sarif([result])
        assert isinstance(out["runs"][0]["results"][0]["message"]["text"], str)


class TestRepoPathInUri:
    """When repo_path is provided, file URIs are made relative to it."""

    def test_absolute_path_stripped_to_relative(self) -> None:
        result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "r",
                    "severity": "ERROR",
                    "message": "m",
                    "file": "/workspace/src/app.py",
                    "start_line": 5,
                }
            ],
            summary={},
        )
        out = to_sarif([result], repo_path="/workspace")
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        assert uri == "src/app.py"

    def test_no_repo_path_keeps_original_uri(self) -> None:
        result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "r",
                    "severity": "ERROR",
                    "message": "m",
                    "file": "/workspace/src/app.py",
                    "start_line": 5,
                }
            ],
            summary={},
        )
        out = to_sarif([result], repo_path=None)
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        assert uri == "/workspace/src/app.py"


class TestPerPackageSarif:
    """When PluginResult.package_root is set, SARIF output reflects the package."""

    def test_single_package_no_change(self):
        """Results with package_root=None produce standard SARIF — no package in tool name."""
        result = PluginResult(
            plugin_name="semgrep",
            findings=[{"rule_id": "r1", "severity": "ERROR", "message": "m1"}],
            summary={},
            package_root=None,
        )
        out = to_sarif([result])
        assert len(out["runs"]) == 1
        assert out["runs"][0]["tool"]["driver"]["name"] == "semgrep"

    def test_multi_package_run_per_plugin_per_package(self):
        """Two packages × 2 plugins = 4 SARIF runs."""
        results = [
            PluginResult(
                plugin_name="semgrep",
                package_root="apps/web",
                findings=[{"rule_id": "r1", "severity": "ERROR", "message": "m"}],
                summary={},
            ),
            PluginResult(
                plugin_name="osv-scanner",
                package_root="apps/web",
                findings=[{"id": "CVE-1", "severity": "high", "summary": "v"}],
                summary={},
            ),
            PluginResult(
                plugin_name="semgrep",
                package_root="libs/core",
                findings=[{"rule_id": "r2", "severity": "WARNING", "message": "m"}],
                summary={},
            ),
            PluginResult(
                plugin_name="osv-scanner",
                package_root="libs/core",
                findings=[{"id": "CVE-2", "severity": "medium", "summary": "v"}],
                summary={},
            ),
        ]
        out = to_sarif(results)
        assert len(out["runs"]) == 4

    def test_multi_package_tool_name_includes_package(self):
        """tool.driver.name is 'semgrep [apps/web]' when package_root is set."""
        result = PluginResult(
            plugin_name="semgrep",
            package_root="apps/web",
            findings=[{"rule_id": "r1", "severity": "ERROR", "message": "m1"}],
            summary={},
        )
        out = to_sarif([result])
        assert out["runs"][0]["tool"]["driver"]["name"] == "semgrep [apps/web]"


class TestFindingCap:
    """max_findings_per_run truncates large result sets."""

    def _make_findings(self, count: int) -> list[dict]:
        return [
            {"rule_id": f"rule-{i}", "severity": "medium", "message": f"finding {i}"}
            for i in range(count)
        ]

    def test_under_cap_passes_all(self) -> None:
        result = PluginResult(
            plugin_name="blast-radius",
            findings=self._make_findings(5),
            summary={},
        )
        out = to_sarif([result], max_findings_per_run=1000)
        assert len(out["runs"][0]["results"]) == 5

    def test_over_cap_truncates_with_notice(self) -> None:
        result = PluginResult(
            plugin_name="blast-radius",
            findings=self._make_findings(2000),
            summary={},
        )
        out = to_sarif([result], max_findings_per_run=100)
        results = out["runs"][0]["results"]
        assert len(results) == 101
        assert results[-1]["ruleId"] == "eedom-truncated"
        assert "1900 additional findings truncated" in results[-1]["message"]["text"]

    def test_truncation_notice_is_note_level(self) -> None:
        result = PluginResult(
            plugin_name="blast-radius",
            findings=self._make_findings(200),
            summary={},
        )
        out = to_sarif([result], max_findings_per_run=50)
        assert out["runs"][0]["results"][-1]["level"] == "note"

    def test_zero_cap_means_no_limit(self) -> None:
        result = PluginResult(
            plugin_name="blast-radius",
            findings=self._make_findings(5000),
            summary={},
        )
        out = to_sarif([result], max_findings_per_run=0)
        assert len(out["runs"][0]["results"]) == 5000
