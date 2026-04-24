"""Syft SBOM scanner.
# tested-by: tests/unit/test_syft_scanner.py

Generates a CycloneDX SBOM for a target directory and writes the raw
JSON to the evidence directory. SBOM generation produces no findings —
the output is consumed by downstream vulnerability scanners.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

from eedom.core.models import ScanResult, ScanResultStatus
from eedom.data.scanners.base import Scanner, run_subprocess_with_timeout

logger = structlog.get_logger()

_TIMEOUT = 60


class SyftScanner(Scanner):
    """Generates a CycloneDX SBOM using Syft."""

    def __init__(self, evidence_dir: Path) -> None:
        self._evidence_dir = evidence_dir

    @property
    def name(self) -> str:
        return "syft"

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        log = logger.bind(scanner=self.name, target=str(target_path))

        cmd = ["syft", f"dir:{target_path}", "-o", "cyclonedx-json"]
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
            return ScanResult.failed(self.name, stderr or f"syft exited with code {returncode}")

        # Parse CycloneDX JSON
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("scanner.parse_error", error=str(exc))
            return ScanResult.failed(self.name, f"failed to parse syft output: {exc}")

        components = data.get("components", [])
        component_count = len(components)

        # Write evidence
        raw_output_path: str | None = None
        try:
            self._evidence_dir.mkdir(parents=True, exist_ok=True)
            evidence_file = self._evidence_dir / "syft-sbom.json"
            evidence_file.write_text(stdout, encoding="utf-8")
            raw_output_path = str(evidence_file)
        except OSError as exc:
            log.warning("scanner.evidence_write_failed", error=str(exc))

        log.info("scanner.complete", components=component_count, elapsed=elapsed)
        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=[],
            raw_output_path=raw_output_path,
            message=f"SBOM generated: {component_count} components detected",
            duration_seconds=elapsed,
        )
