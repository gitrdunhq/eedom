"""Tests for agent tool definitions.
# tested-by: tests/unit/test_agent_tools.py
"""

from __future__ import annotations

from datetime import UTC
from unittest.mock import patch

import pytest

from eedom.core.models import (
    AdmissionDecision,
    AdmissionRequest,
    DecisionVerdict,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ScanResult,
    ScanResultStatus,
)


def _make_decision(verdict: DecisionVerdict = DecisionVerdict.approve) -> AdmissionDecision:
    """Build a minimal AdmissionDecision for testing."""
    from datetime import datetime
    from uuid import uuid4

    req = AdmissionRequest(
        request_id=uuid4(),
        request_type=RequestType.new_package,
        ecosystem="pypi",
        package_name="requests",
        target_version="2.31.0",
        team="platform",
        pr_url="https://github.com/org/repo/pull/1",
        operating_mode=OperatingMode.advise,
        created_at=datetime.now(tz=UTC),
    )
    pol = PolicyEvaluation(
        decision=verdict,
        triggered_rules=[],
        policy_bundle_version="1.0.0",
    )
    scan = ScanResult(
        tool_name="osv-scanner",
        status=ScanResultStatus.success,
        findings=[],
        duration_seconds=1.5,
    )
    return AdmissionDecision(
        decision_id=uuid4(),
        request=req,
        decision=verdict,
        findings=[],
        scan_results=[scan],
        policy_evaluation=pol,
        pipeline_duration_seconds=3.0,
        created_at=datetime.now(tz=UTC),
    )


class TestEvaluateChange:
    def test_returns_decisions_for_valid_diff(self):
        from eedom.agent.tools import evaluate_change

        decision = _make_decision(DecisionVerdict.approve)
        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([decision], [], {}),
        ):
            result = evaluate_change(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "ok"
        assert len(result["decisions"]) == 1
        assert result["decisions"][0]["package_name"] == "requests"

    def test_returns_empty_for_no_dependency_changes(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([], [], {}),
        ):
            result = evaluate_change(
                diff_text="diff --git a/README.md\n+hello",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "ok"
        assert result["decisions"] == []

    def test_handles_pipeline_timeout(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            side_effect=TimeoutError("pipeline timeout"),
        ):
            result = evaluate_change(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "error"
        assert result["error"] == "pipeline_timeout"

    def test_handles_unexpected_exception(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            side_effect=RuntimeError("unexpected"),
        ):
            result = evaluate_change(
                diff_text="diff",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "error"
        assert result["error"] == "pipeline_unavailable"


class TestManifestDetection:
    def test_detects_python_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n"
        result = _detect_manifest_changes(diff)
        assert "pypi" in result
        assert "requirements.txt" in result["pypi"]

    def test_detects_npm_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = (
            "diff --git a/package.json b/package.json\n+new dep\n"
            "diff --git a/yarn.lock b/yarn.lock\n+lock entry\n"
        )
        result = _detect_manifest_changes(diff)
        assert "npm" in result
        assert len(result["npm"]) == 2

    def test_detects_cargo_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = 'diff --git a/Cargo.toml b/Cargo.toml\n+serde = "1.0"\n'
        result = _detect_manifest_changes(diff)
        assert "cargo" in result

    def test_detects_go_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/go.mod b/go.mod\n+require github.com/foo/bar v1.0.0\n"
        result = _detect_manifest_changes(diff)
        assert "golang" in result

    def test_detects_mixed_ecosystems(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = (
            "diff --git a/requirements.txt b/requirements.txt\n+flask\n"
            "diff --git a/package.json b/package.json\n+react\n"
            "diff --git a/Cargo.toml b/Cargo.toml\n+tokio\n"
        )
        result = _detect_manifest_changes(diff)
        assert "pypi" in result
        assert "npm" in result
        assert "cargo" in result

    def test_ignores_non_manifest_files(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/README.md b/README.md\n+hello\n"
        result = _detect_manifest_changes(diff)
        assert result == {}

    def test_detects_ruby_gemfile(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/Gemfile b/Gemfile\n+gem 'rails'\n"
        result = _detect_manifest_changes(diff)
        assert "gem" in result

    def test_detects_composer_json(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/composer.json b/composer.json\n+dep\n"
        result = _detect_manifest_changes(diff)
        assert "composer" in result

    def test_detects_mix_exs(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = 'diff --git a/mix.exs b/mix.exs\n+{:phoenix, "~> 1.7"}\n'
        result = _detect_manifest_changes(diff)
        assert "hex" in result


class TestCheckPackage:
    def test_returns_policy_evaluation(self):
        from eedom.agent.tools import check_package

        decision = _make_decision(DecisionVerdict.approve)
        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([decision], [], {}),
        ):
            result = check_package(
                name="requests",
                version="2.31.0",
                ecosystem="pypi",
            )
        assert result["status"] == "ok"
        assert result["decision"] == "approve"

    def test_handles_missing_package(self):
        from eedom.agent.tools import check_package

        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([], [], {}),
        ):
            result = check_package(
                name="nonexistent-pkg",
                version="0.0.1",
                ecosystem="pypi",
            )
        assert result["status"] == "ok"
        assert result["decision"] == "no_findings"

    def test_rejects_invalid_name(self):
        from eedom.agent.tools import check_package

        result = check_package(
            name="evil\ndiff --git",
            version="1.0.0",
            ecosystem="pypi",
        )
        assert result["status"] == "error"
        assert result["error"] == "invalid_input"


class TestScanCode:
    @pytest.fixture(autouse=True)
    def _set_env(self, monkeypatch):
        monkeypatch.setenv("GATEKEEPER_GITHUB_TOKEN", "ghp_test")
        from eedom.agent.tool_helpers import get_agent_settings

        get_agent_settings.cache_clear()

    def test_returns_categorized_findings(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "python.security.eval-injection",
                    "file": "app.py",
                    "start_line": 10,
                    "end_line": 10,
                    "severity": "ERROR",
                    "message": "Detected eval() usage",
                }
            ],
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+eval(user_input)",
                repo_path=".",
            )
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "python.security.eval-injection"
        assert result["findings"][0]["severity"] == "ERROR"

    def test_returns_empty_for_clean_code(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(plugin_name="semgrep", findings=[])
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "ok"
        assert result["findings"] == []

    def test_handles_semgrep_timeout(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="Command 'semgrep' timed out after 120 seconds",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    def test_handles_semgrep_not_installed(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="[Errno 2] No such file or directory: 'semgrep'",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "error"
        assert "not_installed" in result["error"]

    def test_only_scans_changed_files(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1 +1 @@\n"
            "+new line\n"
            "diff --git a/tests/test_app.py b/tests/test_app.py\n"
            "--- a/tests/test_app.py\n"
            "+++ b/tests/test_app.py\n"
            "@@ -1 +1 @@\n"
            "+new test\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == ["src/app.py", "tests/test_app.py"]

    def test_skips_deleted_files(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/deleted.py b/deleted.py\n"
            "--- a/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-old line\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == []

    def test_skips_deleted_file_with_mode_change(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/deleted.py b/deleted.py\n"
            "old mode 100644\n"
            "new mode 000000\n"
            "deleted file mode 100644\n"
            "index abc1234..0000000\n"
            "--- a/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-old line\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == []


class TestRegistryRouting:
    """Verify that each scan tool routes through PluginRegistry, not direct runner imports.

    TDD: these tests are written FIRST and must fail before implementation.
    """

    @pytest.fixture(autouse=True)
    def _set_env(self, monkeypatch):
        """Satisfy AgentSettings validation present before refactor."""
        monkeypatch.setenv("GATEKEEPER_GITHUB_TOKEN", "ghp_test")
        from eedom.agent.tool_helpers import get_agent_settings

        get_agent_settings.cache_clear()

    _DIFF_PY = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1 @@\n"
        "+x = 1\n"
    )
    _DIFF_YAML = (
        "diff --git a/deploy.yaml b/deploy.yaml\n"
        "--- a/deploy.yaml\n"
        "+++ b/deploy.yaml\n"
        "@@ -1 +1 @@\n"
        "+kind: Deployment\n"
    )

    def test_scan_code_routes_through_semgrep_plugin(self, monkeypatch):
        """scan_code must call registry.get('semgrep').run() — not run_semgrep() directly."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "test.rule",
                    "file": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                    "severity": "ERROR",
                    "message": "test finding",
                }
            ],
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_code(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("semgrep")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "test.rule"

    def test_scan_duplicates_routes_through_cpd_plugin(self, monkeypatch):
        """scan_duplicates must call registry.get('cpd').run() — not run_cpd() directly."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="cpd",
            findings=[
                {
                    "tokens": 80,
                    "lines": 10,
                    "language": "python",
                    "locations": [],
                    "fragment": "",
                }
            ],
            summary={"total": 1, "files_scanned": 2},
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_duplicates(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("cpd")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["duplicates"]) == 1

    def test_scan_k8s_routes_through_kube_linter_plugin(self, monkeypatch):
        """scan_k8s must call registry.get('kube-linter').run() — not run_kube_linter()."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="kube-linter",
            findings=[
                {
                    "check": "no-read-only-root-fs",
                    "message": "container is missing readOnlyRootFilesystem",
                    "remediation": "Set readOnlyRootFilesystem: true",
                    "object_name": "my-deploy",
                    "object_kind": "Deployment",
                    "file": "deploy.yaml",
                }
            ],
            summary={"total": 1},
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_k8s(diff_text=self._DIFF_YAML, repo_path=".")

        mock_registry.get.assert_called_once_with("kube-linter")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1

    def test_analyze_complexity_routes_through_complexity_plugin(self, monkeypatch):
        """analyze_complexity must call registry.get('complexity').run() — not run_complexity()."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "foo",
                    "file": "app.py",
                    "cyclomatic_complexity": 5,
                    "nloc": 20,
                    "maintainability_index": "A (85.0)",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": 5.0,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 20,
                "high_complexity_count": 0,
            },
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.analyze_complexity(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("complexity")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["functions"]) == 1
        assert result["functions"][0]["function"] == "foo"

    def test_scan_code_error_result_surfaces_error_status(self, monkeypatch):
        """When PluginResult.error is set, scan_code returns status='error'."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="Command 'semgrep' timed out after 120 seconds",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_code(diff_text=self._DIFF_PY, repo_path=".")

        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()
