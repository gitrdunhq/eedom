# tested-by: tests/unit/test_github_actions_policy.py
"""GitHub Actions update vetting policy guards."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_ALLOWLIST = _ROOT / ".github" / "actions-allowlist.yml"
_WORKFLOW_POLICY = _WORKFLOWS / "workflow-policy.yml"
_ADR = _ROOT / "docs" / "adr" / "005-github-actions-update-vetting-policy.md"
_CODEOWNERS = _ROOT / "CODEOWNERS"

_USE_LINE = re.compile(r"^\s*uses:\s*(?P<uses>['\"]?[^'\"\s#]+['\"]?)(?P<comment>\s+#.*)?$")
_ACTION_REF = re.compile(r"^(?P<action>[^/@\s]+/[^@\s]+)@(?P<ref>[^@\s]+)$")
_FULL_SHA = re.compile(r"^[A-Fa-f0-9]{40}$")
_VERSION_COMMENT = re.compile(r"#\s*v\d")
_PULL_REQUEST_TARGET_HEAD_PATTERNS = (
    "github.event.pull_request.head",
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
)


def _load_yaml(path: Path) -> dict[object, object]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert isinstance(data, dict), f"{path.relative_to(_ROOT)} must parse to a YAML mapping"
    return data


def _as_mapping(value: object) -> dict[object, object]:
    return value if isinstance(value, dict) else {}


def _as_sequence(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _github_on(workflow: dict[object, object]) -> object:
    # PyYAML follows YAML 1.1, so the GitHub Actions key "on" can parse as True.
    return workflow.get("on", workflow.get(True, {}))


def _workflow_events(workflow: dict[object, object]) -> set[str]:
    on_block = _github_on(workflow)
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {event for event in on_block if isinstance(event, str)}
    if isinstance(on_block, dict):
        return {str(event) for event in on_block}
    return set()


def _workflow_paths() -> list[Path]:
    return sorted(_WORKFLOWS.glob("*.yml"))


def _allowlisted_actions() -> list[str]:
    data = _load_yaml(_ALLOWLIST)
    actions = data.get("actions")
    assert isinstance(actions, list), ".github/actions-allowlist.yml must define an actions list"
    assert all(isinstance(action, str) for action in actions), "allowlisted actions must be strings"
    return actions


def _remote_uses_lines(path: Path) -> list[tuple[int, str, str]]:
    lines: list[tuple[int, str, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = _USE_LINE.match(raw_line)
        if not match:
            continue
        uses = match.group("uses").strip("'\"")
        if uses.startswith("./"):
            continue
        comment = match.group("comment") or ""
        lines.append((line_number, uses, comment))
    return lines


def _workflow_steps(workflow: dict[object, object]) -> list[dict[object, object]]:
    steps: list[dict[object, object]] = []
    for raw_job in _as_mapping(workflow.get("jobs")).values():
        job = _as_mapping(raw_job)
        for raw_step in _as_sequence(job.get("steps")):
            step = _as_mapping(raw_step)
            if step:
                steps.append(step)
    return steps


def _run_text(workflow: dict[object, object]) -> str:
    runs = [step["run"] for step in _workflow_steps(workflow) if isinstance(step.get("run"), str)]
    return "\n".join(runs)


def test_action_allowlist_is_sorted_and_unique() -> None:
    actions = _allowlisted_actions()

    assert actions == sorted(actions), "Keep action allowlist sorted for reviewable diffs"
    assert len(actions) == len(set(actions)), "Action allowlist must not contain duplicates"


def test_workflows_use_only_sha_pinned_allowlisted_actions() -> None:
    allowlist = set(_allowlisted_actions())

    for path in _workflow_paths():
        for line_number, uses, comment in _remote_uses_lines(path):
            location = f"{path.relative_to(_ROOT)}:{line_number}"
            assert not uses.startswith("docker://"), f"{location} uses an unpinned docker action"

            match = _ACTION_REF.match(uses)
            assert match is not None, f"{location} must use owner/repo@ref syntax"

            action = match.group("action")
            assert action in allowlist, f"{location} uses {action}, which is not in the allowlist"

            ref = match.group("ref")
            assert _FULL_SHA.fullmatch(ref), f"{location} must pin {action} to a full commit SHA"
            assert _VERSION_COMMENT.search(comment), (
                f"{location} must include a same-line version comment like '# v4'"
            )


def test_dependabot_updates_github_actions_with_review_labels() -> None:
    dependabot = _load_yaml(_ROOT / ".github" / "dependabot.yml")
    updates = dependabot.get("updates")
    assert isinstance(updates, list), "dependabot.yml must define updates"

    github_actions_updates = [
        update
        for update in updates
        if isinstance(update, dict) and update.get("package-ecosystem") == "github-actions"
    ]
    assert github_actions_updates, "Dependabot must propose GitHub Actions updates"

    root_update = next(
        update for update in github_actions_updates if update.get("directory") == "/"
    )
    labels = root_update.get("labels")
    assert isinstance(labels, list), "GitHub Actions Dependabot updates must define labels"
    assert "github-actions" in labels

    cooldown = root_update.get("cooldown")
    assert isinstance(cooldown, dict), "GitHub Actions updates must define a cooldown"
    assert cooldown.get("default-days") == 14


def test_workflow_policy_runs_read_only_policy_checks() -> None:
    workflow = _load_yaml(_WORKFLOW_POLICY)

    assert "pull_request" in _workflow_events(workflow)
    assert workflow.get("permissions") == {"contents": "read"}

    run_text = _run_text(workflow)
    assert "tests/unit/test_github_actions_policy.py" in run_text
    assert "tests/unit/test_dependabot_policy.py" in run_text
    assert "tests/unit/test_ruff_policy.py" in run_text
    assert "docker.io/library/python@sha256:" in run_text
    assert '-v "$GITHUB_WORKSPACE:/workspace:ro"' in run_text
    assert "UV_PROJECT_ENVIRONMENT=/tmp/eedom-policy-venv" in run_text
    assert "EEDOM_ALLOW_HOST_TESTS" not in run_text


def test_pull_request_target_workflows_do_not_checkout_or_execute_pr_head() -> None:
    for path in _workflow_paths():
        workflow = _load_yaml(path)
        if "pull_request_target" not in _workflow_events(workflow):
            continue

        for step in _workflow_steps(workflow):
            uses = step.get("uses")
            if isinstance(uses, str):
                assert not uses.startswith("actions/checkout@"), (
                    f"{path.relative_to(_ROOT)} must not checkout code under pull_request_target"
                )

            run = step.get("run")
            if isinstance(run, str):
                for pattern in _PULL_REQUEST_TARGET_HEAD_PATTERNS:
                    assert pattern not in run, (
                        f"{path.relative_to(_ROOT)} must not execute pull_request_target code "
                        f"from {pattern}"
                    )


def test_policy_artifacts_are_codeowned_and_documented() -> None:
    assert _ADR.exists(), "Record the GitHub Actions update vetting policy in an ADR"

    codeowners = _CODEOWNERS.read_text(encoding="utf-8")
    required_paths = [
        ".github/actions-allowlist.yml",
        ".github/workflows/workflow-policy.yml",
        "tests/unit/test_github_actions_policy.py",
        "tests/unit/test_dependabot_policy.py",
        "tests/unit/test_ruff_policy.py",
        "docs/adr/005-github-actions-update-vetting-policy.md",
    ]
    for required_path in required_paths:
        assert required_path in codeowners, f"CODEOWNERS must cover {required_path}"
