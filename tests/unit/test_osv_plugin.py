"""Tests for OSV Scanner plugin.
# tested-by: tests/unit/test_osv_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from eedom.core.plugin import PluginCategory
from eedom.plugins.osv_scanner import OsvScannerPlugin

OSV_RESPONSE = {
    "results": [
        {
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.25.1",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-9hjg-9r4m-mvj7",
                            "aliases": ["CVE-2024-47081"],
                            "summary": "Requests proxy leak",
                            "database_specific": {"severity": "MODERATE"},
                            "severity": [],
                        },
                        {
                            "id": "GHSA-x4qr-2fvf-3mr5",
                            "aliases": ["CVE-2023-0286"],
                            "summary": "Vulnerable OpenSSL",
                            "database_specific": {"severity": "HIGH"},
                            "severity": [{"score": 7.5}],
                        },
                    ],
                }
            ]
        }
    ]
}


class TestOsvPlugin:
    def test_name_and_category(self):
        p = OsvScannerPlugin()
        assert p.name == "osv-scanner"
        assert p.category == PluginCategory.dependency

    def test_can_run_with_manifest(self):
        p = OsvScannerPlugin()
        assert p.can_run(["requirements.txt"], Path(".")) is True
        assert p.can_run(["package.json"], Path(".")) is True
        assert p.can_run(["go.mod"], Path(".")) is True

    def test_can_run_without_manifest(self):
        p = OsvScannerPlugin()
        assert p.can_run(["app.py"], Path(".")) is False
        assert p.can_run(["main.tf"], Path(".")) is False

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_extracts_findings_with_cve_ids(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.error == ""
        assert len(result.findings) == 2
        ids = [f["id"] for f in result.findings]
        assert "CVE-2024-47081" in ids
        assert "CVE-2023-0286" in ids

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_severity_mapping(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert by_id["CVE-2024-47081"]["severity"] == "medium"
        assert by_id["CVE-2023-0286"]["severity"] == "high"

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_advisory_urls(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert "nvd.nist.gov" in by_id["CVE-2023-0286"]["url"]
        assert "nvd.nist.gov" in by_id["CVE-2024-47081"]["url"]

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_ghsa_preserved(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert by_id["CVE-2023-0286"]["ghsa"] == "GHSA-x4qr-2fvf-3mr5"

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_summary_counts(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.summary["total"] == 2
        assert result.summary["critical_high"] == 1
        assert result.summary["medium"] == 1

    @patch(
        "eedom.plugins.osv_scanner.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found(self, _mock):
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert "not installed" in result.error

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_clean_repo_no_findings(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.error == ""
        assert result.findings == []

    @patch("eedom.plugins.osv_scanner.subprocess.run")
    def test_render_critical(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        md = p.render(result)
        assert "Critical/High" in md
        assert "CVE-2023-0286" in md
        assert "nvd.nist.gov" in md

    def test_render_error(self):
        from eedom.core.plugin import PluginResult

        p = OsvScannerPlugin()
        result = PluginResult(
            plugin_name="osv-scanner",
            error="not installed",
        )
        md = p.render(result)
        assert "not installed" in md

    def test_render_empty(self):
        from eedom.core.plugin import PluginResult

        p = OsvScannerPlugin()
        result = PluginResult(plugin_name="osv-scanner")
        md = p.render(result)
        assert md == ""
