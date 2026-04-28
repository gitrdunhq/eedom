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
    AuditSinkPort,
    DecisionStorePort,
    EvidenceStorePort,
    PackageIndexPort,
    PullRequestPublisherPort,
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
    audit_sink: AuditSinkPort
    publisher: PullRequestPublisherPort


# ---------------------------------------------------------------------------
# Fake implementations for bootstrap_test() and bootstrap_review()
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
    from eedom.adapters.github_publisher import NullPublisher
    from eedom.adapters.persistence import NullAuditSink, NullDecisionStore, NullEvidenceStore

    return ApplicationContext(
        analyzer_registry=_FakeAnalyzerRegistry(),
        policy_engine=_FakePolicyEngine(),
        tool_runner=_FakeToolRunner(),
        decision_store=NullDecisionStore(),
        evidence_store=NullEvidenceStore(),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=NullPublisher(),
    )


# ---------------------------------------------------------------------------
# bootstrap_review() — minimal context for plugin review command
# ---------------------------------------------------------------------------


def bootstrap_review(registry_factory=None) -> ApplicationContext:
    """Return an ApplicationContext suitable for the review command.

    Uses the real plugin registry (or *registry_factory* when provided) for
    the analyzer and no-op adapters for everything else.  Does NOT require
    EedomSettings so it works without a full production configuration.
    """
    from eedom.adapters.github_publisher import NullPublisher
    from eedom.adapters.persistence import NullAuditSink, NullDecisionStore, NullEvidenceStore
    from eedom.core.subprocess_runner import SubprocessToolRunner

    if registry_factory is None:
        from eedom.plugins import get_default_registry

        registry_factory = get_default_registry

    return ApplicationContext(
        analyzer_registry=registry_factory(),
        policy_engine=_FakePolicyEngine(),
        tool_runner=SubprocessToolRunner(),
        decision_store=NullDecisionStore(),
        evidence_store=NullEvidenceStore(),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=NullPublisher(),
    )


# ---------------------------------------------------------------------------
# Production adapter helpers — keep Null* instantiation out of bootstrap()
# ---------------------------------------------------------------------------


def _make_decision_store(settings: EedomSettings) -> DecisionStorePort:
    """Return the appropriate DecisionStorePort for *settings*.

    Returns a real DecisionRepository when *settings.db_dsn* is set and a
    connection can be established.  Falls back to NullDecisionStore (with a
    warning) when no DSN is configured or the connection attempt fails, so the
    pipeline always proceeds regardless of persistence availability.
    """
    import structlog

    from eedom.adapters.persistence import NullDecisionStore

    log = structlog.get_logger()
    dsn = getattr(settings, "db_dsn", None)
    if not dsn:
        log.warning(
            "decision_store_null",
            msg="No EEDOM_DB_DSN configured — decisions will not be persisted",
        )
        return NullDecisionStore()

    try:
        from eedom.data.db import DecisionRepository

        repo = DecisionRepository(dsn=dsn)
        if not repo.connect():
            log.warning(
                "decision_store_null",
                msg="DB connection failed — falling back to NullDecisionStore",
            )
            return NullDecisionStore()
        return repo
    except Exception:
        log.warning(
            "decision_store_null",
            msg="Failed to initialise DecisionRepository — falling back to NullDecisionStore",
            exc_info=True,
        )
        return NullDecisionStore()


def _make_audit_sink(settings: EedomSettings) -> AuditSinkPort:
    """Return the appropriate AuditSinkPort for *settings*."""
    from eedom.adapters.persistence import NullAuditSink

    return NullAuditSink()


def _make_publisher(settings: EedomSettings) -> PullRequestPublisherPort:
    """Return the appropriate PullRequestPublisherPort for *settings*."""
    from eedom.adapters.github_publisher import NullPublisher

    return NullPublisher()


# ---------------------------------------------------------------------------
# bootstrap(settings)
# ---------------------------------------------------------------------------


def bootstrap(settings: EedomSettings) -> ApplicationContext:
    """Wire concrete adapters from *settings* and return an ApplicationContext.

    All heavy imports are deferred to this function so that import-time cost
    is only paid when the production composition root is actually needed.
    """
    from eedom.adapters.persistence import FileEvidenceStore
    from eedom.core.opa_adapter import OpaRegoAdapter
    from eedom.core.subprocess_runner import SubprocessToolRunner
    from eedom.plugins import get_default_registry

    tool_runner = SubprocessToolRunner()
    registry = get_default_registry()

    # OPA policy path — use the bundled policies directory by default.
    policy_path = str(Path(__file__).parent.parent.parent.parent / "policies" / "policy.rego")

    policy_engine = OpaRegoAdapter(policy_path=policy_path, tool_runner=tool_runner)

    return ApplicationContext(
        analyzer_registry=registry,
        policy_engine=policy_engine,
        tool_runner=tool_runner,
        decision_store=_make_decision_store(settings),
        evidence_store=FileEvidenceStore(base_dir=Path(settings.evidence_path)),
        package_index=_FakePackageIndex(),
        audit_sink=_make_audit_sink(settings),
        publisher=_make_publisher(settings),
    )
