"""Tests for the ScanCode license scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from eedom.core.models import (
    FindingCategory,
    FindingSeverity,
    ScanResultStatus,
)
from eedom.data.scanners.scancode import ScanCodeScanner

# ---------------------------------------------------------------------------
# Fixtures: sample ScanCode JSON output
# ---------------------------------------------------------------------------

SCANCODE_OUTPUT = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.1.0"}],
        "files": [
            {
                "path": "src/eedom/__init__.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "apache-2.0",
                        "license_expression_spdx": "Apache-2.0",
                        "matches": [
                            {
                                "license_expression": "apache-2.0",
                                "score": 100.0,
                                "matched_text": "Licensed under the Apache License, Version 2.0",
                            },
                        ],
                    },
                ],
            },
            {
                "path": "vendor/lib.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "gpl-3.0",
                        "license_expression_spdx": "GPL-3.0-only",
                        "matches": [
                            {
                                "license_expression": "gpl-3.0",
                                "score": 95.5,
                                "matched_text": "GNU General Public License v3",
                            },
                        ],
                    },
                ],
            },
        ],
    }
)

SCANCODE_NO_LICENSES = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.1.0"}],
        "files": [
            {
                "path": "src/main.py",
                "type": "file",
                "license_detections": [],
            },
        ],
    }
)


class TestScanCodeScannerSuccess:
    """Tests for successful ScanCode scans."""

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_parses_licenses_into_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "scancode"
        assert len(result.findings) == 2

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_finding_fields_populated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        apache = result.findings[0]
        assert apache.category == FindingCategory.license
        assert apache.severity == FindingSeverity.info
        assert apache.license_id == "Apache-2.0"
        assert apache.confidence == 100.0
        assert apache.source_tool == "scancode"

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_gpl_license_detected(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        gpl = result.findings[1]
        assert gpl.license_id == "GPL-3.0-only"
        assert gpl.confidence == 95.5

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_no_licenses_returns_empty_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_invokes_correct_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "scancode" in cmd
        assert "--license" in cmd
        assert "--json-pp" in cmd


class TestScanCodeScannerFailure:
    """Tests for ScanCode failure modes."""

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json", "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("eedom.data.scanners.scancode.run_subprocess_with_timeout")
    def test_nonzero_exit_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (1, "", "scancode: error")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
