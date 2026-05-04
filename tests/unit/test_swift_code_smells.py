"""Tests for Swift code smell detection rules.
# tested-by: tests/unit/test_swift_code_smells.py
"""

from __future__ import annotations

from pathlib import Path

import yaml

_POLICIES_DIR = Path(__file__).parent.parent.parent / "policies" / "semgrep"
_SWIFT_SMELLS_YAML = _POLICIES_DIR / "swift-code-smells.yaml"

_REQUIRED_RULE_IDS = {
    "org.swift.force-try",
    "org.swift.force-cast",
    "org.swift.print-in-source",
    "org.swift.notification-center-post",
    "org.swift.notification-center-observer",
    "org.swift.userdefaults-write",
    "org.swift.dispatch-main-async",
    "org.swift.todo-fixme",
}

# Rules that smell in production code but are fine in tests
_SOURCE_SCOPED_IDS = {
    "org.swift.print-in-source",
    "org.swift.dispatch-main-async",
    "org.swift.todo-fixme",
}

# Rules that are crash risks — must be WARNING or higher
_CRASH_RISK_IDS = {
    "org.swift.force-try",
    "org.swift.force-cast",
}


class TestSwiftCodeSmellsYamlStructure:
    def test_file_exists(self) -> None:
        assert _SWIFT_SMELLS_YAML.exists(), f"Expected {_SWIFT_SMELLS_YAML} to exist"

    def test_is_valid_yaml_with_rules_key(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        assert "rules" in data, "swift-code-smells.yaml must have a top-level 'rules' key"
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) >= 8, f"Expected >= 8 Swift smell rules, got {len(data['rules'])}"

    def test_all_rules_have_required_fields(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        for rule in data["rules"]:
            rid = rule.get("id", "<unknown>")
            assert "id" in rule, f"Rule missing 'id': {rule}"
            assert "message" in rule, f"Rule {rid} missing 'message'"
            assert "severity" in rule, f"Rule {rid} missing 'severity'"
            assert "languages" in rule, f"Rule {rid} missing 'languages'"
            assert rule["severity"] in {
                "ERROR",
                "WARNING",
                "INFO",
            }, f"Rule {rid} has invalid severity: {rule['severity']}"
            has_pattern = any(
                k in rule for k in ("pattern", "patterns", "pattern-either", "pattern-regex")
            )
            assert has_pattern, f"Rule {rid} has no pattern field"

    def test_all_rules_target_swift(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        for rule in data["rules"]:
            assert "swift" in rule.get(
                "languages", []
            ), f"Rule {rule['id']} must target 'swift' in languages"

    def test_required_rule_ids_present(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        rule_ids = {r["id"] for r in data["rules"]}
        for expected_id in _REQUIRED_RULE_IDS:
            assert expected_id in rule_ids, f"Missing required rule: {expected_id}"

    def test_source_scoped_rules_exclude_test_paths(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        for rule in data["rules"]:
            if rule["id"] in _SOURCE_SCOPED_IDS:
                excludes = rule.get("paths", {}).get("exclude", [])
                assert excludes, f"Rule {rule['id']} should exclude test paths but has none"

    def test_crash_risk_rules_are_warning_or_error(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        for rule in data["rules"]:
            if rule["id"] in _CRASH_RISK_IDS:
                assert rule["severity"] in {"WARNING", "ERROR"}, (
                    f"Crash-risk rule {rule['id']} must be WARNING or ERROR, "
                    f"got {rule['severity']}"
                )

    def test_rule_ids_are_namespaced(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        for rule in data["rules"]:
            assert rule["id"].startswith(
                "org.swift."
            ), f"Rule {rule['id']} must be namespaced under org.swift.*"

    def test_no_duplicate_rule_ids(self) -> None:
        data = yaml.safe_load(_SWIFT_SMELLS_YAML.read_text())
        ids = [r["id"] for r in data["rules"]]
        assert len(ids) == len(
            set(ids)
        ), f"Duplicate rule IDs found: {[i for i in ids if ids.count(i) > 1]}"
