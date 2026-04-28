# tested-by: tests/unit/test_bootstrap.py
"""Application composition root — wires concrete adapters behind port contracts.

Three public symbols:
  - ApplicationContext — dataclass holding all wired port dependencies
  - bootstrap(settings) -> ApplicationContext — production wiring
  - bootstrap_test() -> ApplicationContext — in-memory fakes for unit tests
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from eedom.core.policy_port import PolicyDecision, PolicyEnginePort, PolicyInput
from eedom.core.ports import (
    AnalyzerRegistryPort,
    DecisionStorePort,
    EvidenceStorePort,
    PackageIndexPort,
)
from eedom.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

if TYPE_CHECKING:
    from eedom.core.config import EedomSettings


# ---------------------------------------------------------------------------
# ApplicationContext
# ---------------------------------------------------------------------------


@dataclass
class ApplicationContext:
    """Holds all wired port dependencies for one application instance."""

    analyzer_registry: AnalyzerRegistryPort
    policy_engine: PolicyEnginePort
    tool_runner: ToolRunnerPort
    decision_store: DecisionStorePort
    evidence_store: EvidenceStorePort
    package_index: PackageIndexPort


# ---------------------------------------------------------------------------
# Fake implementations for bootstrap_test()
# ---------------------------------------------------------------------------


class _FakeAnalyzerRegistry:
    """No-op analyzer registry — never reaches real scanners."""

    def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
        return []

    def list(self, category=None, names=None) -> list:
        return []


class _FakePolicyEngine:
    """Always-approve policy engine — never invokes OPA."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision:
        return PolicyDecision(verdict="approve")


class _FakeDecisionStore:
    """No-op decision store — never writes to a real DB."""

    def save_decision(self, decision) -> None:
        return None


class _FakeEvidenceStore:
    """No-op evidence store — never hits the filesystem."""

    def write_artifact(self, path: str, content: bytes) -> str:
        return ""


class _FakePackageIndex:
    """No-op package index — never makes real network calls."""

    def get_package_info(self, name: str, ecosystem: str) -> dict:
        return {}


class _FakeToolRunner:
    """No-op tool runner — never spawns real subprocesses."""

    def run(self, invocation: ToolInvocation) -> ToolResult:
        return ToolResult(exit_code=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# bootstrap_test()
# ---------------------------------------------------------------------------


def bootstrap_test() -> ApplicationContext:
    """Return an ApplicationContext wired with all-fake implementations.

    Safe to call without any real infrastructure (no DB, no OPA, no
    subprocesses, no filesystem side-effects).
    """
    return ApplicationContext(
        analyzer_registry=_FakeAnalyzerRegistry(),
        policy_engine=_FakePolicyEngine(),
        tool_runner=_FakeToolRunner(),
        decision_store=_FakeDecisionStore(),
        evidence_store=_FakeEvidenceStore(),
        package_index=_FakePackageIndex(),
    )


# ---------------------------------------------------------------------------
# bootstrap(settings)
# ---------------------------------------------------------------------------


def bootstrap(settings: EedomSettings) -> ApplicationContext:
    """Wire concrete adapters from *settings* and return an ApplicationContext.

    All heavy imports are deferred to this function so that import-time cost
    is only paid when the production composition root is actually needed.
    """
    from eedom.core.opa_adapter import OpaRegoAdapter
    from eedom.core.registry import PluginRegistry
    from eedom.core.subprocess_runner import SubprocessToolRunner

    tool_runner = SubprocessToolRunner()
    registry = PluginRegistry()

    # OPA policy path — use the bundled policies directory by default.
    policy_path = str(Path(__file__).parent.parent.parent.parent / "policies" / "policy.rego")

    policy_engine = OpaRegoAdapter(policy_path=policy_path, tool_runner=tool_runner)

    # No production concrete implementations exist yet for DecisionStore,
    # EvidenceStore, or PackageIndex — use the same fakes as bootstrap_test()
    # until adapters are added.
    # TODO: replace with real adapters when production implementations land.
    return ApplicationContext(
        analyzer_registry=registry,
        policy_engine=policy_engine,
        tool_runner=tool_runner,
        decision_store=_FakeDecisionStore(),
        evidence_store=_FakeEvidenceStore(),
        package_index=_FakePackageIndex(),
    )
