# tested-by: tests/unit/test_policy_port.py
"""PolicyEnginePort contract — typed boundary between pipeline and policy engine.

Defines the three public symbols used at the policy evaluation seam:
  - PolicyInput   — inputs gathered by the pipeline
  - PolicyDecision — verdict + reasons returned by any policy engine
  - PolicyEnginePort — runtime-checkable Protocol that policy engines must satisfy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from eedom.core.plugin import PluginFinding


@dataclass
class PolicyInput:
    """Inputs passed to a policy engine for evaluation."""

    findings: list[PluginFinding]
    packages: list[dict]
    config: dict


@dataclass
class PolicyDecision:
    """Result returned by a policy engine after evaluating a PolicyInput."""

    verdict: str
    deny_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    triggered_rules: list[str] = field(default_factory=list)


@runtime_checkable
class PolicyEnginePort(Protocol):
    """Protocol that every policy engine implementation must satisfy."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision: ...
