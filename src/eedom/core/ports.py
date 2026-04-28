# tested-by: tests/unit/test_ports.py
"""Port protocols for eedom's hexagonal architecture boundaries.

These @runtime_checkable Protocol classes define the contracts that
adapters must satisfy. No business logic lives here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class AnalyzerRegistryPort(Protocol):
    """Contract for running all registered analyzer plugins."""

    def run_all(self, files: list, repo_path: Path, **kwargs) -> list: ...


@runtime_checkable
class DecisionStorePort(Protocol):
    """Contract for persisting policy decisions."""

    def save_decision(self, decision) -> None: ...


@runtime_checkable
class EvidenceStorePort(Protocol):
    """Contract for writing evidence artifacts."""

    def write_artifact(self, path: str, content: bytes) -> str: ...


@runtime_checkable
class PackageIndexPort(Protocol):
    """Contract for querying package metadata from an index."""

    def get_package_info(self, name: str, ecosystem: str) -> dict: ...
