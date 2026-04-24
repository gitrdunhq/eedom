"""ScanCode license scanner.
# tested-by: tests/unit/test_scancode_scanner.py

Invokes scancode-toolkit to detect license declarations and maps
results into Finding objects with category=LICENSE.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

from eedom.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from eedom.data.scanners.base import Scanner, run_subprocess_with_timeout

logger = structlog.get_logger()

_TIMEOUT = 60


class ScanCodeScanner(Scanner):
    """Detects license declarations using ScanCode."""

    def __init__(self, evidence_dir: Path) -> None:
        self._evidence_dir = evidence_dir

    @property
    def name(self) -> str:
        return "scancode"

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        log = logger.bind(scanner=self.name, target=str(target_path))

        try:
            self._evidence_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("scanner.evidence_dir_failed", error=str(exc))

        output_file = self._evidence_dir / "scancode-output.json"
        cmd = [
            "scancode",
            "--license",
            "--json-pp",
            str(output_file),
            str(target_path),
        ]

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=cmd, timeout=_TIMEOUT)
        elapsed = time.monotonic() - start

        # Timeout
        if returncode is None and stderr == "timeout exceeded":
            log.warning("scanner.timeout")
            return ScanResult.timeout(self.name, _TIMEOUT)

        # Binary not found
        if returncode is None:
            log.warning("scanner.not_installed", error=stderr)
            return ScanResult.not_installed(self.name)

        # Non-zero exit
        if returncode != 0:
            log.warning("scanner.failed", returncode=returncode, stderr=stderr)
            return ScanResult.failed(self.name, stderr or f"scancode exited with code {returncode}")

        # ScanCode writes to the output file, but also emits to stdout.
        # Try reading from stdout first (the --json-pp output), then fall back
        # to reading the file.
        raw_json = stdout
        if not raw_json.strip():
            try:
                raw_json = output_file.read_text(encoding="utf-8")
            except OSError as exc:
                log.warning("scanner.read_output_failed", error=str(exc))
                return ScanResult.failed(self.name, f"could not read scancode output: {exc}")

        # Parse JSON
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("scanner.parse_error", error=str(exc))
            return ScanResult.failed(self.name, f"failed to parse scancode output: {exc}")

        findings = _extract_findings(data)
        log.info("scanner.complete", findings=len(findings), elapsed=elapsed)

        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=findings,
            raw_output_path=str(output_file),
            duration_seconds=elapsed,
            message=f"{len(findings)} license detections found",
        )


def _extract_findings(data: dict) -> list[Finding]:
    """Walk the ScanCode JSON and build Finding objects for license detections."""
    findings: list[Finding] = []

    for file_entry in data.get("files", []):
        file_path = file_entry.get("path", "unknown")
        for detection in file_entry.get("license_detections", []):
            spdx_id = detection.get("license_expression_spdx", "")
            if not spdx_id:
                spdx_id = detection.get("license_expression", "unknown")

            # Pick the best confidence score from matches
            best_score: float | None = None
            for match in detection.get("matches", []):
                score = match.get("score")
                if score is not None and (best_score is None or score > best_score):
                    best_score = score

            findings.append(
                Finding(
                    severity=FindingSeverity.info,
                    category=FindingCategory.license,
                    description=f"License {spdx_id} detected in {file_path}",
                    source_tool="scancode",
                    package_name=file_path,
                    version="",
                    license_id=spdx_id,
                    confidence=best_score,
                )
            )

    return findings
