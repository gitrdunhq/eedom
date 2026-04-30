# tested-by: tests/unit/test_deterministic_architecture_guards.py
"""Deterministic architecture boundary guards for layer violations (#265).

Detects when agent and core orchestration components inappropriately cross
presentation/core/data boundaries. These tests intentionally encode architecture
invariants. They may fail while the corresponding architecture bugs are open.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #265 — fix the source code, then this test goes green",
    strict=False,
)

import ast
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "eedom"

# Architecture layer definitions
_PRESENTATION_MODULES = frozenset(
    {
        "eedom.cli",
        "eedom.webhook",
    }
)

_CORE_MODULES = frozenset(
    {
        "eedom.core",
    }
)

_DATA_MODULES = frozenset(
    {
        "eedom.data",
        "eedom.data.scanners",
        "eedom.data.scanners.base",
        "eedom.data.scanners.osv",
        "eedom.data.scanners.syft",
        "eedom.data.scanners.trivy",
        "eedom.data.scanners.scancode",
    }
)

_ADAPTER_MODULES = frozenset(
    {
        "eedom.adapters",
        "eedom.adapters.persistence",
        "eedom.adapters.github_publisher",
        "eedom.adapters.repo_snapshot",
    }
)

_AGENT_MODULES = frozenset(
    {
        "eedom.agent",
        "eedom.agent.tools",
        "eedom.agent.main",
        "eedom.agent.config",
        "eedom.agent.prompt",
        "eedom.agent.tool_helpers",
    }
)

# Core orchestration files that should stay behind ports
_CORE_ORCHESTRATION_PATHS = (
    _SRC / "core" / "orchestrator.py",
    _SRC / "core" / "pipeline.py",
    _SRC / "core" / "bootstrap.py",
    _SRC / "core" / "use_cases.py",
)

# Agent files that should not cross into data layer
_AGENT_PATHS = (
    _SRC / "agent" / "main.py",
    _SRC / "agent" / "tools.py",
    _SRC / "agent" / "tool_helpers.py",
)


def _python_files(root: Path) -> list[Path]:
    """Get all Python files under root, excluding __pycache__."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    """Get repo-relative path string."""
    return path.relative_to(_REPO).as_posix()


def _imported_modules(tree: ast.Module) -> list[tuple[str, int]]:
    """Extract all imported module names with their line numbers."""
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.module, node.lineno))
            # Also handle relative imports by getting the full module path
            if node.level > 0:
                # For relative imports, we keep them as-is but note they're relative
                for alias in node.names:
                    # Construct the full import path for checking
                    full_import = f"{node.module}.{alias.name}" if node.module else alias.name
                    imports.append((full_import, node.lineno))
    return imports


def _is_module_in_set(module: str, module_set: frozenset[str]) -> bool:
    """Check if a module is in the given set (exact match or prefix match)."""
    if module in module_set:
        return True
    # Check if any module in the set is a prefix
    return any(module.startswith(f"{mod}.") for mod in module_set)


def _module_matches_any(module: str, prefixes: Sequence[str]) -> bool:
    """Check if module matches any of the given prefixes."""
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes)


def _get_top_level_imports(path: Path) -> list[tuple[str, int]]:
    """Parse file and get top-level (not nested) import statements."""
    tree = _parse(path)
    imports: list[tuple[str, int]] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.module, node.lineno))
            # Add imported names for potential cross-layer detection
            for alias in node.names:
                if node.module:
                    full_path = f"{node.module}.{alias.name}"
                    imports.append((full_path, node.lineno))

    return imports


@pytest.mark.xfail(reason="deterministic bug detector for #265", strict=False)
def test_core_orchestration_does_not_import_data_layer() -> None:
    """#265: Core orchestration must not directly import data layer modules.

    Core should depend on ports/interfaces, not concrete data implementations.
    Data layer modules implement ports defined in core.
    """
    violations: list[str] = []
    data_prefixes = tuple(_DATA_MODULES | _ADAPTER_MODULES)

    for path in _CORE_ORCHESTRATION_PATHS:
        if not path.exists():
            continue

        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            if _module_matches_any(module, data_prefixes):
                violations.append(
                    f"{_rel(path)}:{lineno}: core orchestration imports data layer {module}"
                )

    assert violations == [], (
        "Core orchestration must not directly import data layer modules.\n"
        "Core should depend on ports, not concrete data implementations:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #265", strict=False)
def test_agent_does_not_import_data_layer_directly() -> None:
    """#265: Agent layer must not directly import data layer modules.

    Agent tools should go through core use-cases/ports, not directly to data.
    """
    violations: list[str] = []
    data_prefixes = tuple(_DATA_MODULES)
    adapter_prefixes = tuple(_ADAPTER_MODULES)

    for path in _AGENT_PATHS:
        if not path.exists():
            continue

        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            # Check for direct data layer imports
            if _module_matches_any(module, data_prefixes):
                violations.append(
                    f"{_rel(path)}:{lineno}: agent imports data layer directly {module}"
                )
            # Check for adapter imports (should go through ports)
            if _module_matches_any(module, adapter_prefixes):
                violations.append(f"{_rel(path)}:{lineno}: agent imports adapter directly {module}")

    assert violations == [], (
        "Agent layer must not directly import data layer or adapter modules.\n"
        "Agent should use core use-cases and ports:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #265", strict=False)
def test_presentation_does_not_import_data_layer() -> None:
    """#265: Presentation layer (CLI/webhook) must not directly import data layer.

    Presentation should only interact with core via use-cases/ports.
    """
    violations: list[str] = []
    data_prefixes = tuple(_DATA_MODULES)

    presentation_roots = (
        _SRC / "cli",
        _SRC / "webhook",
    )

    for root in presentation_roots:
        if not root.exists():
            continue

        for path in _python_files(root):
            tree = _parse(path)
            for module, lineno in _imported_modules(tree):
                if _module_matches_any(module, data_prefixes):
                    violations.append(
                        f"{_rel(path)}:{lineno}: presentation imports data layer {module}"
                    )

    assert violations == [], (
        "Presentation layer must not directly import data layer modules.\n"
        "Presentation should use core use-cases and ports:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #265", strict=False)
def test_data_layer_does_not_import_presentation_or_agent() -> None:
    """#265: Data layer must not import presentation or agent layers.

    Data is an outer layer implementing core ports; it should not know about
    presentation or agent concerns.
    """
    violations: list[str] = []
    upper_layer_prefixes = tuple(_PRESENTATION_MODULES | _AGENT_MODULES)

    data_root = _SRC / "data"
    if not data_root.exists():
        pytest.skip("No data layer found")

    for path in _python_files(data_root):
        # Skip __init__.py as it may re-export
        if path.name == "__init__.py":
            continue

        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            if _module_matches_any(module, upper_layer_prefixes):
                violations.append(f"{_rel(path)}:{lineno}: data layer imports upper layer {module}")

    assert violations == [], (
        "Data layer must not import presentation or agent layers.\n"
        "Data implements core ports and should not depend on upper layers:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #265", strict=False)
def test_adapter_imports_stay_within_boundary() -> None:
    """#265: Adapters must only import from core (ports/models) and data.

    Adapters implement core ports and may use data layer utilities,
    but must not import presentation or agent layers.
    """
    violations: list[str] = []
    forbidden_prefixes = tuple(_PRESENTATION_MODULES | _AGENT_MODULES)

    adapters_root = _SRC / "adapters"
    if not adapters_root.exists():
        pytest.skip("No adapters found")

    for path in _python_files(adapters_root):
        if path.name == "__init__.py":
            continue

        tree = _parse(path)
        for module, lineno in _imported_modules(tree):
            if _module_matches_any(module, forbidden_prefixes):
                violations.append(
                    f"{_rel(path)}:{lineno}: adapter imports forbidden layer {module}"
                )

    assert violations == [], (
        "Adapters must not import presentation or agent layers.\n"
        "Adapters implement core ports and may use data layer:\n" + "\n".join(violations)
    )
