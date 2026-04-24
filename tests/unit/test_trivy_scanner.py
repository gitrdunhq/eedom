"""Tests for the Trivy vulnerability scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from eedom.core.models import (
    FindingCategory,
    FindingSeverity,
    ScanResultStatus,
)
from eedom.data.scanners.trivy import TrivyScanner

# ---------------------------------------------------------------------------
# Fixtures: sample Trivy JSON output
# ---------------------------------------------------------------------------

TRIVY_OUTPUT_WITH_VULNS = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                        "Title": "Unintended leak of Proxy-Authorization header",
                        "Description": "Requests leaks Proxy-Authorization headers.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-32681",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-35195",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.32.0",
                        "Severity": "CRITICAL",
                        "Title": "cert verification bypass",
                        "Description": "Requests sessions do not verify certs properly.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-35195",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-43804",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.5",
                        "FixedVersion": "1.26.18",
                        "Severity": "HIGH",
                        "Title": "Cookie leak on redirect",
                        "Description": "urllib3 leaks cookies on cross-origin redirect.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-43804",
                    },
                ],
            },
        ],
    }
)

TRIVY_OUTPUT_ZERO_VULNS = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": None,
            },
        ],
    }
)

TRIVY_OUTPUT_EMPTY_RESULTS = json.dumps({"SchemaVersion": 2, "Results": []})


class TestTrivyScannerSuccess:
    """Tests for successful Trivy scans."""

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_parses_vulnerabilities_into_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "trivy"
        assert len(result.findings) == 3

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_finding_fields_populated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        finding = result.findings[0]
        assert finding.category == FindingCategory.vulnerability
        assert finding.advisory_id == "CVE-2023-32681"
        assert finding.source_tool == "trivy"
        assert finding.package_name == "requests"
        assert finding.version == "2.25.0"
        assert finding.advisory_url == "https://avd.aquasec.com/nvd/cve-2023-32681"

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_critical(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        critical_finding = next(f for f in result.findings if f.advisory_id == "CVE-2024-35195")
        assert critical_finding.severity == FindingSeverity.critical

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_high(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        high_finding = next(f for f in result.findings if f.advisory_id == "CVE-2023-43804")
        assert high_finding.severity == FindingSeverity.high

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_medium(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        med_finding = next(f for f in result.findings if f.advisory_id == "CVE-2023-32681")
        assert med_finding.severity == FindingSeverity.medium

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_zero_vulns_returns_success_empty_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_ZERO_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_empty_results_returns_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_invokes_correct_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "trivy" in cmd
        assert "fs" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--scanners" in cmd
        assert "vuln" in cmd


class TestTrivyScannerFailure:
    """Tests for Trivy failure modes."""

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json", "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("eedom.data.scanners.trivy.run_subprocess_with_timeout")
    def test_nonzero_exit_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (2, "", "fatal error")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
