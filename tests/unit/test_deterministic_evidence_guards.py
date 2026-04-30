# tested-by: tests/unit/test_deterministic_evidence_guards.py
"""Deterministic evidence integrity guards for known bug classes.

These tests intentionally encode evidence invariants as static checks.
They may fail while the corresponding bugs are still open.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "eedom"
_SEAL_FILE = _SRC / "core" / "seal.py"


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


def _get_function_body(tree: ast.Module, func_name: str) -> list[ast.stmt]:
    """Extract the body statements of a named function."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node.body
    return []


def _contains_call(body: list[ast.stmt], call_name: str) -> bool:
    """Check if any statement in the body contains a call to the named function."""
    for stmt in body:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call):
                # Check for direct name call
                if isinstance(child.func, ast.Name) and child.func.id == call_name:
                    return True
                # Check for attribute call (e.g., path.rglob)
                if isinstance(child.func, ast.Attribute) and child.func.attr == call_name:
                    return True
    return False


def _contains_iterdir_or_rglob(body: list[ast.stmt]) -> bool:
    """Check if body iterates over directory contents (iterdir or rglob)."""
    return _contains_call(body, "iterdir") or _contains_call(body, "rglob")


def _contains_unexpected_file_check(body: list[ast.stmt]) -> bool:
    """Check if body explicitly checks for unexpected/extra files."""
    source = ast.unparse(body)
    # Look for checks that compare actual files against expected manifest
    check_terms = [
        "unexpected",
        "extra",
        "additional",
        "surplus",
        "not in manifest",
        "not in artifacts",
        "len(",
        "count",
    ]
    return any(term in source.lower() for term in check_terms)


def test_verify_seal_checks_for_unexpected_files() -> None:
    """#264: Evidence seal verification must detect unexpected added files.

    The verify_seal function should check that the evidence directory contains
    exactly the files listed in the manifest — no more, no less. Currently it
    only validates the files in the manifest, ignoring any extra files that
    may have been added.
    """
    tree = _parse(_SEAL_FILE)
    body = _get_function_body(tree, "verify_seal")

    # The fix requires two things:
    # 1. Iterating over actual directory contents (to find all files)
    # 2. Checking those against the manifest (to detect unexpected files)

    has_directory_iteration = _contains_iterdir_or_rglob(body)
    has_unexpected_file_check = _contains_unexpected_file_check(body)

    violations: list[str] = []

    if not has_directory_iteration:
        violations.append(
            f"{_rel(_SEAL_FILE)}: verify_seal does not iterate over directory contents "
            "(needed to find all files including unexpected ones)"
        )

    if not has_unexpected_file_check:
        violations.append(
            f"{_rel(_SEAL_FILE)}: verify_seal does not check for unexpected/extra files "
            "that are not in the manifest"
        )

    assert not violations, (
        "Seal verification must detect unexpected added files by:\n"
        "1. Iterating over actual directory contents\n"
        "2. Comparing against the manifest to find extra files\n\n" + "\n".join(violations)
    )
