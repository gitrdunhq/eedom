"""Tests for gitleaks plugin.
# tested-by: tests/unit/test_gitleaks_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from eedom.plugins.gitleaks import GitleaksPlugin

from eedom.core.plugin import PluginCategory

LEAK_OUTPUT = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "StartLine": 5,
            "EndLine": 5,
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIA****EXAMPLE",
            "File": "config.py",
            "Entropy": 3.5,
            "Fingerprint": "abc123:config.py:aws-access-token:5",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "StartLine": 12,
            "EndLine": 12,
            "Match": "api_key = 'sk-prod-abc123'",
            "Secret": "sk-prod-****",
            "File": "src/app.py",
            "Entropy": 4.2,
            "Fingerprint": "def456:src/app.py:generic-api-key:12",
        },
    ]
)

CLEAN_OUTPUT = "[]"


class TestGitleaksPlugin:
    def test_name_and_category(self):
        p = GitleaksPlugin()
        assert p.name == "gitleaks"
        assert p.category == PluginCategory.supply_chain

    def test_can_run_always(self):
        p = GitleaksPlugin()
        assert p.can_run(["app.py"], Path(".")) is True

    @patch("eedom.plugins.gitleaks.subprocess.run")
    def test_clean_scan(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CLEAN_OUTPUT
        p = GitleaksPlugin()
        result = p.run(["app.py"], Path("/workspace"))
        assert result.error == ""
        assert len(result.findings) == 0

    @patch("eedom.plugins.gitleaks.subprocess.run")
    def test_detects_leaks(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = LEAK_OUTPUT
        p = GitleaksPlugin()
        result = p.run(["config.py"], Path("/workspace"))
        assert len(result.findings) == 2
        assert result.findings[0]["rule"] == "aws-access-token"
        assert result.findings[0]["file"] == "config.py"
        assert result.findings[0]["severity"] == "critical"
        assert result.summary["leaks"] == 2

    @patch("eedom.plugins.gitleaks.subprocess.run")
    def test_secrets_not_in_findings(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = LEAK_OUTPUT
        p = GitleaksPlugin()
        result = p.run(["config.py"], Path("/workspace"))
        for f in result.findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in str(f)
            assert "sk-prod-abc123" not in str(f)

    @patch(
        "eedom.plugins.gitleaks.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found(self, _mock):
        p = GitleaksPlugin()
        result = p.run(["app.py"], Path("."))
        assert "NOT_INSTALLED" in result.error

    @patch("eedom.plugins.gitleaks.subprocess.run")
    def test_render_leaks(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = LEAK_OUTPUT
        p = GitleaksPlugin()
        result = p.run(["config.py"], Path("/workspace"))
        md = p.render(result)
        assert "Secrets" in md
        assert "aws-access-token" in md
        assert "config.py" in md
        assert "AKIAIOSFODNN7EXAMPLE" not in md

    def test_render_clean(self):
        from eedom.core.plugin import PluginResult

        p = GitleaksPlugin()
        result = PluginResult(plugin_name="gitleaks")
        assert p.render(result) == ""

    def test_render_error(self):
        from eedom.core.plugin import PluginResult

        p = GitleaksPlugin()
        result = PluginResult(plugin_name="gitleaks", error="not installed")
        assert "not installed" in p.render(result)
