"""Actionability classification for scanner findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from eedom.core.plugin import Actionability, PluginResult

__all__ = ["Actionability", "ActionabilitySummary", "classify_findings"]

_CRITICAL_HIGH = {"critical", "high"}


@dataclass
class ActionabilitySummary:
    actionable: list[dict] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)
    owner_action: list[dict] = field(default_factory=list)
    actionable_count: int = 0
    blocked_count: int = 0
    owner_action_count: int = 0
    blocked_by_source: dict[str, list[dict]] = field(default_factory=dict)
    owner_action_by_source: dict[str, list[dict]] = field(default_factory=dict)
    summary_text: str = ""


def _is_actionable(finding: dict) -> bool:
    fv = finding.get("fixed_version", "")
    return bool(fv and fv.strip())


_DEPENDENCY_SOURCES = {"trivy", "osv", "osv-scanner"}
_OWNER_ACTION_SOURCES = {"opa"}


def _is_dependency_source(result: PluginResult) -> bool:
    if result.plugin_name in _OWNER_ACTION_SOURCES:
        return False
    return result.category == "dependency" or result.plugin_name in _DEPENDENCY_SOURCES


def _severity_counts(findings: list[dict]) -> str:
    crit = sum(1 for f in findings if f.get("severity", "") == "critical")
    high = sum(1 for f in findings if f.get("severity", "") == "high")
    parts = []
    if crit:
        parts.append(f"{crit} CRITICAL")
    if high:
        parts.append(f"{high} HIGH")
    return " + ".join(parts)


def _finding_noun(count: int) -> str:
    return "finding" if count == 1 else "findings"


def _finding_verb(count: int) -> str:
    return "requires" if count == 1 else "require"


def _build_summary_text(
    actionable: list[dict],
    blocked: list[dict],
    owner_action: list[dict],
) -> str:
    total = len(actionable) + len(blocked) + len(owner_action)
    if total == 0:
        return "No findings."

    crit_high_blocked = sum(1 for f in blocked if f.get("severity", "") in _CRITICAL_HIGH)
    blocked_severity = _severity_counts(blocked)
    owner_severity = _severity_counts(owner_action)

    if owner_action and not actionable and not blocked:
        count = len(owner_action)
        prefix = (
            f"{owner_severity} {_finding_noun(count)}"
            if owner_severity
            else f"{count} {_finding_noun(count)}"
        )
        return f"{prefix} {_finding_verb(count)} code/config changes in this PR."

    if blocked and not actionable and not owner_action:
        # All blocked
        if crit_high_blocked > 0:
            severity_str = (
                blocked_severity if blocked_severity else f"{crit_high_blocked} CRITICAL/HIGH"
            )
            return (
                f"{severity_str} findings — none actionable by you. "
                "All in upstream dependencies at latest release."
            )
        return f"{len(blocked)} findings — none actionable by you."

    if actionable and not blocked and not owner_action:
        # All actionable
        return f"All {len(actionable)} findings have available fixes."

    parts = []
    if actionable:
        verb = "has" if len(actionable) == 1 else "have"
        parts.append(f"{len(actionable)} {_finding_noun(len(actionable))} {verb} available fixes")
    if owner_action:
        parts.append(
            f"{len(owner_action)} {_finding_noun(len(owner_action))} "
            f"{_finding_verb(len(owner_action))} code/config changes"
        )
    if blocked:
        verb = "is" if len(blocked) == 1 else "are"
        parts.append(f"{len(blocked)} {_finding_noun(len(blocked))} {verb} blocked on upstream")
    return ". ".join(parts) + "."


def classify_findings(results: list[PluginResult]) -> ActionabilitySummary:
    """Classify all findings across plugin results by actionability.

    Args:
        results: Plugin results from all scanners.

    Returns:
        ActionabilitySummary with actionable/blocked split, counts,
        per-source grouping, and human-readable summary text.
    """
    actionable: list[dict] = []
    blocked: list[dict] = []
    owner_action: list[dict] = []
    blocked_by_source: dict[str, list[dict]] = {}
    owner_action_by_source: dict[str, list[dict]] = {}

    for result in results:
        for finding in result.findings:
            if _is_actionable(finding):
                actionable.append(finding)
            elif _is_dependency_source(result):
                blocked.append(finding)
                blocked_by_source.setdefault(result.plugin_name, []).append(finding)
            else:
                owner_action.append(finding)
                owner_action_by_source.setdefault(result.plugin_name, []).append(finding)

    return ActionabilitySummary(
        actionable=actionable,
        blocked=blocked,
        owner_action=owner_action,
        actionable_count=len(actionable),
        blocked_count=len(blocked),
        owner_action_count=len(owner_action),
        blocked_by_source=blocked_by_source,
        owner_action_by_source=owner_action_by_source,
        summary_text=_build_summary_text(actionable, blocked, owner_action),
    )
