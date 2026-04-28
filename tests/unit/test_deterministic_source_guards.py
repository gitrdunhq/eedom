# tested-by: tests/unit/test_deterministic_source_guards.py
"""Deterministic source-architecture guards for known bug classes.

These tests intentionally encode current architecture invariants as static
checks. They may fail while the corresponding product-code bugs are still open.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "eedom"

_PORT_FILES = (
    _SRC / "core" / "ports.py",
    _SRC / "core" / "policy_port.py",
    _SRC / "core" / "tool_runner.py",
)
_SUBPROCESS_TIMEOUT_FILES = (
    _SRC / "adapters" / "github_publisher.py",
    _SRC / "adapters" / "repo_snapshot.py",
)
_SECRET_BOUNDARY_FILES = (
    _SRC / "core" / "config.py",
    _SRC / "agent" / "config.py",
    _SRC / "webhook" / "config.py",
    _SRC / "adapters" / "github_publisher.py",
)
_CORE_ORCHESTRATION_FILES = (
    _SRC / "core" / "bootstrap.py",
    _SRC / "core" / "pipeline.py",
    _SRC / "core" / "orchestrator.py",
)

_STATE_FIELD_NAMES = {
    "action",
    "category",
    "decision",
    "mode",
    "operating_mode",
    "request_type",
    "state",
    "status",
    "verdict",
}
_SECRET_FIELD_RE = re.compile(
    r"(api[_-]?key|credential|dsn|password|private[_-]?key|secret|token)", re.IGNORECASE
)
_TESTED_BY_RE = re.compile(r"#\s*tested-by:\s*([^\s,(]+)")
_AGENT_DISALLOWED_IMPORT_PREFIXES = (
    "eedom.adapters",
    "eedom.data",
    "eedom.plugins",
)
_AGENT_DISALLOWED_CORE_IMPORTS = {
    "eedom.core.orchestrator",
    "eedom.core.pipeline",
    "eedom.core.sbom_diff",
}
_CORE_ORCHESTRATION_DISALLOWED_PREFIXES = (
    "eedom.adapters",
    "eedom.data",
)


def _python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


def _annotation_text(annotation: ast.AST | None) -> str:
    if annotation is None:
        return "<missing>"
    return ast.unparse(annotation)


def _node_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _node_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _contains_name(node: ast.AST | None, names: set[str]) -> bool:
    if node is None:
        return False
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _contains_bare_container(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"dict", "Dict", "list", "List"}:
            parent_is_subscript = any(
                isinstance(parent, ast.Subscript) and parent.value is child
                for parent in ast.walk(node)
            )
            if not parent_is_subscript:
                return True
    return False


def _contains_any(node: ast.AST | None) -> bool:
    return _contains_name(node, {"Any"})


def _is_plain_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Name) and node.id == "str"


def _is_secret_str_annotation(node: ast.AST | None) -> bool:
    return _contains_name(node, {"SecretStr"})


def _annotation_problems(name: str, annotation: ast.AST | None) -> list[str]:
    problems: list[str] = []
    if _contains_any(annotation):
        problems.append("uses Any")
    if _contains_bare_container(annotation):
        problems.append("uses bare dict/list")
    if name in _STATE_FIELD_NAMES and _is_plain_str(annotation):
        problems.append("uses raw str for state field")
    return problems


def _iter_function_annotations(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, int, ast.AST | None]]:
    annotations: list[tuple[str, int, ast.AST | None]] = []
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if node.args.vararg is not None:
        args.append(node.args.vararg)
    if node.args.kwarg is not None:
        args.append(node.args.kwarg)

    for arg in args:
        if arg.arg == "self":
            continue
        annotations.append(
            (f"{_rel(path)}:{arg.lineno}: {node.name}({arg.arg})", arg.lineno, arg.annotation)
        )
    if node.returns is not None:
        annotations.append(
            (f"{_rel(path)}:{node.lineno}: {node.name} return", node.lineno, node.returns)
        )
    return annotations


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _imported_modules(tree: ast.Module) -> list[tuple[str, int]]:
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.module, node.lineno))
    return imports


def _module_matches(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(f"{prefix}.")


def test_core_port_contracts_do_not_expose_untyped_containers_any_or_string_state() -> None:
    """#219: core ports should expose typed contracts, not raw containers or string states."""
    violations: list[str] = []

    for path in _PORT_FILES:
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                for problem in _annotation_problems(node.target.id, node.annotation):
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: {node.target.id}: "
                        f"{_annotation_text(node.annotation)} {problem}"
                    )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for label, _lineno, annotation in _iter_function_annotations(path, node):
                    name = label.rsplit("(", maxsplit=1)[-1].rstrip(")")
                    if label.endswith(" return"):
                        name = "return"
                    for problem in _annotation_problems(name, annotation):
                        violations.append(f"{label}: {_annotation_text(annotation)} {problem}")

    assert violations == [], (
        "Core port contracts must use typed boundary models/enums instead of raw dict/list, "
        "Any, or raw string state:\n" + "\n".join(violations)
    )


def test_source_files_have_current_tested_by_annotations() -> None:
    """#224: every source file needs a tested-by annotation that points at an existing test."""
    missing: list[str] = []
    stale: list[str] = []

    for path in _python_files(_SRC):
        refs = _TESTED_BY_RE.findall(path.read_text())
        if not refs:
            missing.append(_rel(path))
            continue
        for ref in refs:
            if not ref.startswith("tests/"):
                stale.append(f"{_rel(path)}: annotation is not a tests/ path: {ref}")
                continue
            if not (_REPO / ref).exists():
                stale.append(f"{_rel(path)}: stale tested-by target: {ref}")

    assert missing == [] and stale == [], (
        "Every source file must have current # tested-by annotations.\n"
        f"Missing:\n{chr(10).join(missing) or '<none>'}\n"
        f"Stale:\n{chr(10).join(stale) or '<none>'}"
    )


def test_github_publisher_and_repo_snapshot_subprocesses_use_explicit_timeouts() -> None:
    """#226: subprocess calls in GitHub publishing and repo snapshots must be bounded."""
    violations: list[str] = []

    for path in _SUBPROCESS_TIMEOUT_FILES:
        tree = _parse(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node.func) != "subprocess.run":
                continue
            timeout_keywords = [kw for kw in node.keywords if kw.arg == "timeout"]
            has_timeout = bool(timeout_keywords) and not any(
                isinstance(kw.value, ast.Constant) and kw.value.value is None
                for kw in timeout_keywords
            )
            if not has_timeout:
                violations.append(f"{_rel(path)}:{node.lineno}: subprocess.run without timeout=")

    assert violations == [], (
        "GitHub publisher and repo snapshot subprocess calls must pass explicit timeouts:\n"
        + "\n".join(violations)
    )


def test_secret_bearing_trust_boundaries_use_secretstr() -> None:
    """#227: secret-bearing settings and adapter constructor params must use SecretStr."""
    violations: list[str] = []

    for path in _SECRET_BOUNDARY_FILES:
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if _SECRET_FIELD_RE.search(node.target.id) and not _is_secret_str_annotation(
                    node.annotation
                ):
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: {node.target.id}: "
                        f"{_annotation_text(node.annotation)} should be SecretStr"
                    )
            elif isinstance(node, ast.FunctionDef) and node.name == "__init__":
                for arg in [*node.args.args, *node.args.kwonlyargs]:
                    if arg.arg == "self" or not _SECRET_FIELD_RE.search(arg.arg):
                        continue
                    if not _is_secret_str_annotation(arg.annotation):
                        violations.append(
                            f"{_rel(path)}:{arg.lineno}: __init__({arg.arg}): "
                            f"{_annotation_text(arg.annotation)} should be SecretStr"
                        )

    assert violations == [], (
        "Secret-bearing settings and trust-boundary constructor params must use "
        "pydantic.SecretStr:\n" + "\n".join(violations)
    )


def test_agent_and_core_orchestration_imports_stay_behind_ports() -> None:
    """#231: presentation and core orchestration must not import concrete lower tiers."""
    violations: list[str] = []

    for path in _python_files(_SRC / "agent"):
        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            if any(_module_matches(module, prefix) for prefix in _AGENT_DISALLOWED_IMPORT_PREFIXES):
                violations.append(f"{_rel(path)}:{lineno}: agent imports concrete module {module}")
            if module in _AGENT_DISALLOWED_CORE_IMPORTS:
                violations.append(
                    f"{_rel(path)}:{lineno}: agent imports core orchestration {module}"
                )

    for path in _CORE_ORCHESTRATION_FILES:
        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            if any(
                _module_matches(module, prefix)
                for prefix in _CORE_ORCHESTRATION_DISALLOWED_PREFIXES
            ):
                violations.append(
                    f"{_rel(path)}:{lineno}: core orchestration imports concrete module {module}"
                )

    assert violations == [], (
        "Agent presentation code and core orchestration should depend on use-cases/ports, "
        "not concrete lower-tier modules:\n" + "\n".join(violations)
    )
