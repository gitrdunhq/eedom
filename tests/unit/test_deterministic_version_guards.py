# tested-by: tests/unit/test_deterministic_version_guards.py
"""Deterministic detector for semver version comparison (Issue #227).

This module detects string comparison used for version comparison instead of
proper semantic versioning (semver) comparison in the _classify_version_change
function. Issue #193 describes the bug where InvalidVersion fallback uses
string comparison instead of semver, causing incorrect upgrade/downgrade
classifications.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "eedom"
_SBOM_DIFF_FILE = _SRC / "core" / "sbom_diff.py"


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _find_version_string_comparison(tree: ast.Module) -> list[tuple[int, str]]:
    """
    Find string comparison operations in version exception handlers.

    This detects the bug pattern from issue #193:
    - A try block that attempts semver parsing
    - An except InvalidVersion block
    - Inside the except: string comparison (old_ver < new_ver) instead of semver

    Returns list of (line_number, source_snippet) tuples.
    """
    violations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            # Look for except handlers that catch InvalidVersion
            for handler in node.handlers:
                # Check if this is an InvalidVersion exception handler
                is_invalid_version_handler = False

                if handler.type:
                    handler_type_str = ast.unparse(handler.type)
                    # Match InvalidVersion or packaging.version.InvalidVersion
                    if "InvalidVersion" in handler_type_str:
                        is_invalid_version_handler = True

                if is_invalid_version_handler:
                    # Now check the body for string comparison
                    for stmt in handler.body:
                        # Walk the handler body to find comparison operations
                        for child in ast.walk(stmt):
                            if isinstance(child, ast.Compare):
                                # Check if this is a < or > comparison
                                if any(isinstance(op, (ast.Lt, ast.Gt)) for op in child.ops):
                                    source = ast.unparse(child)
                                    lineno = getattr(child, "lineno", 0)

                                    # Check if comparing version-like variable names
                                    left_str = ast.unparse(child.left)
                                    right_str = ""
                                    if child.comparators:
                                        right_str = ast.unparse(child.comparators[0])

                                    # Detect version-related variable names
                                    version_patterns = [
                                        r"old.*ver",
                                        r"new.*ver",
                                        r"old_ver",
                                        r"new_ver",
                                        r"old.*version",
                                        r"new.*version",
                                        r"version.*old",
                                        r"version.*new",
                                    ]

                                    has_version_var = any(
                                        re.search(pattern, left_str, re.IGNORECASE)
                                        or re.search(pattern, right_str, re.IGNORECASE)
                                        for pattern in version_patterns
                                    )

                                    if has_version_var:
                                        violations.append((lineno, source))

    return violations


def _find_classify_version_function(tree: ast.Module) -> ast.FunctionDef | None:
    """Find the _classify_version_change function in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_classify_version_change":
            return node
    return None


def _find_string_comparison_in_function(func: ast.FunctionDef) -> list[tuple[int, str, str]]:
    """
    Find all string comparisons (< or >) with version-like variables in a function.

    Returns list of (line_number, comparison_source, context) tuples.
    """
    violations: list[tuple[int, str, str]] = []

    for node in ast.walk(func):
        if isinstance(node, ast.Compare):
            # Check if this is a < or > comparison
            if any(isinstance(op, (ast.Lt, ast.Gt)) for op in node.ops):
                source = ast.unparse(node)
                lineno = getattr(node, "lineno", 0)

                # Get the operands
                left_str = ast.unparse(node.left)
                right_str = ""
                if node.comparators:
                    right_str = ast.unparse(node.comparators[0])

                # Detect version-related variable names
                version_patterns = [
                    r"old.*ver",
                    r"new.*ver",
                    r"old_ver",
                    r"new_ver",
                    r"old.*version",
                    r"new.*version",
                    r"version.*old",
                    r"version.*new",
                    r"old_ver\b",
                    r"new_ver\b",
                ]

                has_version_var = any(
                    re.search(pattern, left_str, re.IGNORECASE)
                    or re.search(pattern, right_str, re.IGNORECASE)
                    for pattern in version_patterns
                )

                if has_version_var:
                    # Determine context (in try vs except block)
                    context = "unknown"
                    for parent in ast.walk(func):
                        if isinstance(parent, ast.Try):
                            # Check if this node is inside the try block
                            try_body = parent.body
                            except_handlers = parent.handlers

                            # Simple heuristic: check line numbers
                            parent_lineno = getattr(parent, "lineno", 0)
                            if lineno > parent_lineno:
                                # Check if in an except handler
                                for handler in except_handlers:
                                    handler_start = getattr(handler, "lineno", 0)
                                    handler_end = getattr(handler, "end_lineno", handler_start + 10)
                                    if handler_start <= lineno <= handler_end:
                                        handler_type = (
                                            ast.unparse(handler.type)
                                            if handler.type
                                            else "Exception"
                                        )
                                        context = f"except {handler_type}"
                                        break
                                else:
                                    # Check if in try body
                                    try_end = getattr(parent, "end_lineno", parent_lineno + 20)
                                    for handler in except_handlers:
                                        handler_start = getattr(handler, "lineno", try_end)
                                        if parent_lineno < lineno < handler_start:
                                            context = "try block"
                                            break

                    violations.append((lineno, source, context))

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector — issue #227 (parent #193)",
    strict=False,
)
def test_227_classify_version_change_no_string_comparison_in_except() -> None:
    """Detect string comparison in InvalidVersion exception handler.

    Issue #193: Package version comparison uses string compare instead of semver.

    The _classify_version_change function should use semver comparison for
    valid versions. When InvalidVersion is raised, the fallback currently
    uses string comparison (old_ver < new_ver) which produces incorrect results:
    - "10.0.0" < "9.0.0" lexicographically (wrong)
    - "10.0.0" > "9.0.0" semantically (correct)

    The fix requires:
        - Use packaging.version.Version for all comparisons
        - Never fall back to string comparison for versions
        - Consider using a proper semver library or normalizing versions

    Acceptance criteria:
        - No string comparison in InvalidVersion exception handler
        - All version comparisons use semver-aware logic
    """
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")

    tree = _parse(_SBOM_DIFF_FILE)

    # Find the _classify_version_change function
    func = _find_classify_version_function(tree)
    if func is None:
        pytest.skip("_classify_version_change function not found")

    violations: list[str] = []

    # Find all string comparisons with version variables in the function
    comparison_violations = _find_string_comparison_in_function(func)

    # Filter to only those in exception handlers
    for lineno, source, context in comparison_violations:
        if "except" in context.lower():
            violations.append(
                f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: " f"String comparison in {context}: {source}"
            )

    assert violations == [], (
        "_classify_version_change must not use string comparison "
        "in exception handlers (issue #193). "
        "Use semver-aware comparison instead:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector — issue #227 (parent #193)",
    strict=False,
)
def test_227_classify_version_change_uses_semver_not_string_comparison() -> None:
    """Verify _classify_version_change uses semver comparison exclusively.

    This test detects any string comparison operations (< or >) on version
    strings in the _classify_version_change function, which indicates the
    bug from issue #193 where string comparison is used instead of semver.
    """
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")

    content = _SBOM_DIFF_FILE.read_text()
    tree = _parse(_SBOM_DIFF_FILE)

    # Find the _classify_version_change function
    func = _find_classify_version_function(tree)
    if func is None:
        pytest.skip("_classify_version_change function not found")

    violations: list[str] = []

    # Find the function's line range
    func_start = getattr(func, "lineno", 0)
    func_end = getattr(func, "end_lineno", func_start + 50)

    # Check the raw source for version string comparison patterns
    lines = content.split("\n")
    in_function = False

    for lineno, line in enumerate(lines, start=1):
        # Track if we're inside the function
        if lineno == func_start:
            in_function = True
        if lineno > func_end:
            break

        if in_function:
            # Look for patterns like: old_ver < new_ver, old_ver > new_ver
            # These indicate string comparison being used
            patterns = [
                r"old_ver\s*[<>]\s*new_ver",
                r"new_ver\s*[<>]\s*old_ver",
                r"old_version\s*[<>]\s*new_version",
                r"new_version\s*[<>]\s*old_version",
            ]

            for pattern in patterns:
                if re.search(pattern, line):
                    violations.append(
                        f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: "
                        f"String version comparison detected: {line.strip()[:80]}"
                    )
                    break

    assert violations == [], (
        "_classify_version_change must use semver comparison, not string comparison. "
        "String comparison of versions produces incorrect results for multi-digit versions "
        '(e.g., "10.0.0" < "9.0.0" lexicographically but semantically greater):\n'
        + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector — issue #227 (parent #193)",
    strict=False,
)
def test_227_invalid_version_fallback_detected() -> None:
    """Detect the InvalidVersion fallback mechanism that uses string comparison.

    This test specifically targets the exception handler introduced in the fix
    for issue #193. It detects when InvalidVersion triggers a fallback to
    string comparison, which is the root cause of the bug.
    """
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")

    tree = _parse(_SBOM_DIFF_FILE)

    violations: list[str] = []

    # Find all Try nodes
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                # Check if this handles InvalidVersion
                if handler.type:
                    handler_type = ast.unparse(handler.type)
                    if "InvalidVersion" in handler_type:
                        # Found the InvalidVersion handler
                        # Now check its body for version comparison
                        for stmt in handler.body:
                            stmt_str = ast.unparse(stmt)

                            # Look for comparison operations
                            if re.search(
                                r"\b(old_ver|new_ver|old_version|new_version)\b.*[<>]", stmt_str
                            ) or re.search(
                                r"[<>].*\b(old_ver|new_ver|old_version|new_version)\b", stmt_str
                            ):
                                lineno = getattr(stmt, "lineno", 0)
                                violations.append(
                                    f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: "
                                    f"InvalidVersion handler uses string comparison: {stmt_str[:80]}"
                                )

    assert violations == [], (
        "The InvalidVersion exception handler must not use string comparison. "
        "This is the bug described in issue #193. "
        "Consider using a proper semver fallback or rejecting invalid versions:\n"
        + "\n".join(violations)
    )
