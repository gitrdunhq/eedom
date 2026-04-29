"""Tests for opengrep runner — binary name and local-only rules.
# tested-by: tests/unit/test_opengrep_runner.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from eedom.plugins._runners.semgrep_runner import run_semgrep


class TestOpengrepBinaryName:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_opengrep_binary(self, mock_run):
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "opengrep"
        assert "semgrep" not in cmd[0]


class TestLocalRulesOnly:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_no_registry_rulesets_in_command(self, mock_run):
        """No p/ or r/ registry prefixes — only local rule paths."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        for val in config_values:
            assert not val.startswith("p/"), f"Registry ruleset {val} should not be used"
            assert not val.startswith("r/"), f"Registry ruleset {val} should not be used"

    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_local_policies_dir(self, mock_run):
        """Should use policies/semgrep/ when it exists."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        repo = str(Path(__file__).resolve().parent.parent.parent)
        run_semgrep(["app.py"], repo)
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert any("policies/semgrep" in v for v in config_values)
