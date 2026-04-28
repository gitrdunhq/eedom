# tested-by: tests/unit/test_ports.py
"""Port protocols for eedom's hexagonal architecture boundaries.

These @runtime_checkable Protocol classes define the contracts that
adapters must satisfy. No business logic lives here.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


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


@runtime_checkable
class RepoSnapshotPort(Protocol):
    """Contract for checking out a repository snapshot at a given ref."""

    def checkout_ref(self, ref: str) -> Path: ...

    def cleanup(self) -> None: ...


@runtime_checkable
class PullRequestPublisherPort(Protocol):
    """Contract for publishing review artifacts back to a pull request."""

    def post_comment(self, repo: str, pr_num: int, body: str) -> bool: ...

    def post_review(self, repo: str, pr_num: int, review: dict) -> bool: ...

    def add_label(self, repo: str, pr_num: int, label: str) -> bool: ...


@dataclasses.dataclass
class ReviewReport:
    """Structured output produced by the review pipeline."""

    verdict: str
    security_score: float
    quality_score: float
    plugin_results: list[Any]
    actionability: dict[str, Any]


@runtime_checkable
class ReportRendererPort(Protocol):
    """Contract for rendering a ReviewReport to a string."""

    def render(self, report: ReviewReport) -> str: ...


@runtime_checkable
class AuditSinkPort(Protocol):
    """Contract for sealing audit evidence and appending audit log entries."""

    def seal(self, artifact_refs: list[str]) -> str: ...

    def append_audit_log(self, entry: dict) -> None: ...
