# tested-by: tests/unit/test_deterministic_optional_surface_guards.py
"""Deterministic detector for optional surface test coverage (#246).

These tests detect when optional copilot, webhook, and parquet surfaces
are skipped in the default test suite via pytest.importorskip. This is
a regression risk because optional surfaces may silently break when
their tests are always skipped in CI.

Bug: #246 — Add deterministic rule for #212
Parent: #212 — Optional copilot, webhook, and parquet surfaces skip in default tests
Epic: #146
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = _ROOT / "tests"

# Optional surface modules that need non-skipping test coverage
_OPTIONAL_SURFACES = {
    "copilot": [
        _ROOT / "src" / "eedom" / "agent" / "main.py",
        _ROOT / "src" / "eedom" / "agent" / "tools.py",
    ],
    "webhook": [
        _ROOT / "src" / "eedom" / "webhook" / "config.py",
        _ROOT / "src" / "eedom" / "webhook" / "server.py",
    ],
    "parquet": [
        _ROOT / "src" / "eedom" / "data" / "parquet_writer.py",
    ],
}

# Extra names that trigger pytest.importorskip
_EXTRA_MARKERS = {
    "copilot": ["agent_framework", "starlette"],
    "webhook": ["starlette"],
    "parquet": ["pyarrow"],
}


def _rel(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_pytest_importorskip_call(node: ast.AST, extra_markers: list[str]) -> bool:
    """Check if node is a pytest.importorskip() call with any of the extra markers."""
    if not isinstance(node, ast.Call):
        return False
    call_name = _call_name(node.func)
    if call_name != "pytest.importorskip":
        return False
    # Check if first arg (module name) matches any of our extra markers
    if node.args:
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            return first_arg.value in extra_markers
    return False


def _has_module_level_importorskip_for_extra(path: Path, extra_markers: list[str]) -> bool:
    """Check if test file has module-level pytest.importorskip for optional extras."""
    for node in _parse(path).body:
        # Look for module-level expressions (calls) or assignments with importorskip
        if isinstance(node, ast.Expr):
            if _is_pytest_importorskip_call(node.value, extra_markers):
                return True
        # Also check for pytestmark assignment with importorskip
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "pytestmark":
                    if _is_pytest_importorskip_call(node.value, extra_markers):
                        return True
    return False


def _tested_by_refs(path: Path) -> list[Path]:
    """Extract # tested-by references from source file."""
    refs: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        marker = "# tested-by:"
        if marker not in line:
            continue
        raw_ref = line.split(marker, maxsplit=1)[1].strip().split()[0].rstrip(",")
        if raw_ref.startswith("tests/"):
            refs.append(_ROOT / raw_ref)
    return refs


def _count_non_importorskip_tests(test_path: Path, extra_markers: list[str]) -> int:
    """Count test functions that are not guarded by module-level importorskip."""
    if not test_path.exists():
        return 0

    # If module-level importorskip exists, all tests are skipped
    if _has_module_level_importorskip_for_extra(test_path, extra_markers):
        return 0

    text = test_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(test_path))

    test_count = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if it's a test function
            if node.name.startswith("test_"):
                test_count += 1

    return test_count


def test_246_copilot_surfaces_have_non_skipping_tests() -> None:
    """#246: Copilot agent surfaces must have tests that don't always skip.

        Detects when copilot modules (agent/main.py, agent/tools.py) only have
    test coverage via files with module-level pytest.importorskip("agent_framework").
    """
    violations: list[str] = []
    extra_markers = _EXTRA_MARKERS["copilot"]

    for source_path in _OPTIONAL_SURFACES["copilot"]:
        if not source_path.exists():
            violations.append(f"{_rel(source_path)}: source file does not exist")
            continue

        refs = _tested_by_refs(source_path)
        if not refs:
            violations.append(f"{_rel(source_path)}: no # tested-by target")
            continue

        # Count non-skipping tests across all referenced test files
        total_non_skipping = sum(
            _count_non_importorskip_tests(ref, extra_markers) for ref in refs if ref.exists()
        )

        if total_non_skipping == 0:
            ref_list = ", ".join(_rel(ref) for ref in refs if ref.exists())
            violations.append(
                f"{_rel(source_path)}: all tests use module-level pytest.importorskip "
                f"for {extra_markers} ({ref_list})"
            )

    assert violations == [], (
        f"BUG #246/#212: Copilot surfaces must have at least one test that runs in the default suite\n"
        f"(not skipped via pytest.importorskip for {extra_markers}):\n" + "\n".join(violations)
    )


def test_246_webhook_surfaces_have_non_skipping_tests() -> None:
    """#246: Webhook surfaces must have tests that don't always skip.

    Detects when webhook modules (webhook/config.py, webhook/server.py) only have
    test coverage via files with module-level pytest.importorskip("starlette").
    """
    violations: list[str] = []
    extra_markers = _EXTRA_MARKERS["webhook"]

    for source_path in _OPTIONAL_SURFACES["webhook"]:
        if not source_path.exists():
            violations.append(f"{_rel(source_path)}: source file does not exist")
            continue

        refs = _tested_by_refs(source_path)
        if not refs:
            violations.append(f"{_rel(source_path)}: no # tested-by target")
            continue

        # Count non-skipping tests across all referenced test files
        total_non_skipping = sum(
            _count_non_importorskip_tests(ref, extra_markers) for ref in refs if ref.exists()
        )

        if total_non_skipping == 0:
            ref_list = ", ".join(_rel(ref) for ref in refs if ref.exists())
            violations.append(
                f"{_rel(source_path)}: all tests use module-level pytest.importorskip "
                f"for {extra_markers} ({ref_list})"
            )

    assert violations == [], (
        f"BUG #246/#212: Webhook surfaces must have at least one test that runs in the default suite\n"
        f"(not skipped via pytest.importorskip for {extra_markers}):\n" + "\n".join(violations)
    )


def test_246_parquet_surfaces_have_non_skipping_tests() -> None:
    """#246: Parquet surfaces must have tests that don't always skip.

            Detects when parquet module (data/parquet_writer.py) only has
    test coverage via files with module-level pytest.importorskip("pyarrow").
    """
    violations: list[str] = []
    extra_markers = _EXTRA_MARKERS["parquet"]

    for source_path in _OPTIONAL_SURFACES["parquet"]:
        if not source_path.exists():
            violations.append(f"{_rel(source_path)}: source file does not exist")
            continue

        refs = _tested_by_refs(source_path)
        if not refs:
            violations.append(f"{_rel(source_path)}: no # tested-by target")
            continue

        # Count non-skipping tests across all referenced test files
        total_non_skipping = sum(
            _count_non_importorskip_tests(ref, extra_markers) for ref in refs if ref.exists()
        )

        if total_non_skipping == 0:
            ref_list = ", ".join(_rel(ref) for ref in refs if ref.exists())
            violations.append(
                f"{_rel(source_path)}: all tests use module-level pytest.importorskip "
                f"for {extra_markers} ({ref_list})"
            )

    assert violations == [], (
        f"BUG #246/#212: Parquet surfaces must have at least one test that runs in the default suite\n"
        f"(not skipped via pytest.importorskip for {extra_markers}):\n" + "\n".join(violations)
    )


def test_246_all_optional_surfaces_have_tested_by_markers() -> None:
    """#246: All optional surfaces must have # tested-by markers.

        Detects when optional copilot, webhook, or parquet surfaces are missing
    the required # tested-by marker that links them to their test files.
    """
    violations: list[str] = []

    for surface_name, paths in _OPTIONAL_SURFACES.items():
        for source_path in paths:
            if not source_path.exists():
                violations.append(f"[{surface_name}] {_rel(source_path)}: file does not exist")
                continue

            refs = _tested_by_refs(source_path)
            if not refs:
                violations.append(
                    f"[{surface_name}] {_rel(source_path)}: missing # tested-by marker"
                )

    assert (
        violations == []
    ), "BUG #246/#212: All optional surfaces must have # tested-by markers:\n" + "\n".join(
        violations
    )
