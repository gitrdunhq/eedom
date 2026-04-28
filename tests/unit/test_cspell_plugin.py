"""Tests for CspellPlugin — dictionary flags and locale.
# tested-by: tests/unit/test_cspell_plugin.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from eedom.core.plugin import PluginCategory, PluginResult
from eedom.plugins.cspell import CSPELL_DICTIONARIES, CspellPlugin


class TestCspellDictionaryConstant:
    def test_dictionaries_constant_is_non_empty(self):
        assert len(CSPELL_DICTIONARIES) > 0

    def test_dictionaries_includes_python(self):
        assert "python" in CSPELL_DICTIONARIES

    def test_dictionaries_includes_typescript(self):
        assert "typescript" in CSPELL_DICTIONARIES

    def test_dictionaries_includes_golang(self):
        assert "golang" in CSPELL_DICTIONARIES

    def test_dictionaries_includes_docker(self):
        assert "docker" in CSPELL_DICTIONARIES

    def test_dictionaries_includes_k8s(self):
        assert "k8s" in CSPELL_DICTIONARIES

    def test_dictionaries_includes_en_ca(self):
        assert "en-CA" in CSPELL_DICTIONARIES


class TestCspellPluginCommand:
    @patch("eedom.plugins.cspell.subprocess.run")
    def test_command_includes_dictionary_flags(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--dictionary" in cmd
        assert "--dictionaries" not in cmd

    @patch("eedom.plugins.cspell.subprocess.run")
    def test_command_includes_all_expected_dictionaries(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        actual_dicts = [
            cmd[i + 1] for i, value in enumerate(cmd) if value == "--dictionary"
        ]
        for expected in CSPELL_DICTIONARIES:
            assert expected in actual_dicts, f"{expected!r} missing from --dictionaries arg"

    @patch("eedom.plugins.cspell.subprocess.run")
    def test_command_includes_locale_en_ca(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--locale" in cmd
        locale_idx = cmd.index("--locale")
        assert cmd[locale_idx + 1] == "en-CA"

    @patch("eedom.plugins.cspell.subprocess.run")
    def test_dictionaries_arg_contains_python_typescript_golang_docker_k8s(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        actual_dicts = [
            cmd[i + 1] for i, value in enumerate(cmd) if value == "--dictionary"
        ]
        for d in ("python", "typescript", "golang", "docker", "k8s"):
            assert d in actual_dicts, f"{d!r} missing from dictionaries value"


class TestCspellPluginBasics:
    def test_name_and_category(self):
        p = CspellPlugin()
        assert p.name == "cspell"
        assert p.category == PluginCategory.quality

    def test_can_run_with_files(self):
        p = CspellPlugin()
        assert p.can_run(["app.py"], Path(".")) is True

    def test_can_run_empty_files(self):
        p = CspellPlugin()
        assert p.can_run([], Path(".")) is False

    @patch(
        "eedom.plugins.cspell.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found_returns_error(self, _mock):
        p = CspellPlugin()
        result = p.run(["app.py"], Path("."))
        assert "not installed" in result.error

    @patch("eedom.plugins.cspell.subprocess.run")
    def test_clean_output_no_findings(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        result = p.run(["app.py"], Path("."))
        assert result.error == ""
        assert result.findings == []

    @patch("eedom.plugins.cspell.subprocess.run")
    def test_misspelling_produces_finding(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = (
            "src/app.py:10:5 - Unknown word (coontainer) Suggestions: [container]"
        )
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        result = p.run(["src/app.py"], Path("."))
        assert len(result.findings) == 1
        assert result.findings[0]["word"] == "coontainer"

    def test_render_clean(self):
        p = CspellPlugin()
        result = PluginResult(plugin_name="cspell", findings=[])
        assert p.render(result) == ""

    def test_render_error(self):
        p = CspellPlugin()
        result = PluginResult(plugin_name="cspell", error="not installed")
        md = p.render(result)
        assert "not installed" in md


class TestCspellFallbacks:
    @patch("eedom.plugins.cspell.subprocess.run")
    def test_retries_without_dictionaries_on_dictionary_error(self, mock_run):
        first = subprocess.CompletedProcess(
            args=["cspell"],
            returncode=1,
            stdout="",
            stderr="Unknown dictionary: softwareTerms",
        )
        second = subprocess.CompletedProcess(
            args=["cspell"],
            returncode=1,
            stdout=(
                "src/app.py:10:5 - Unknown word (coontainer) "
                "Suggestions: [container]"
            ),
            stderr="",
        )
        mock_run.side_effect = [first, second]

        p = CspellPlugin()
        result = p.run(["src/app.py"], Path("."))

        assert len(result.findings) == 1
        assert result.findings[0]["word"] == "coontainer"
        assert mock_run.call_count == 2
