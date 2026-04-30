"""Deterministic detector for missing entry point signature validation in plugin loader.

Issue #240 — Parent bug: #206 — Epic: #146

Detects that plugin loader imports modules without validating that discovered
plugin classes have valid/expected signatures before instantiation.
"""

# tested-by: tests/unit/test_deterministic_loader_guards.py

from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _get_discover_plugins_ast_node() -> ast.FunctionDef | None:
    """Parse registry.py and find the discover_plugins function AST node."""
    registry_path = Path(__file__).parent.parent.parent / "src" / "eedom" / "core" / "registry.py"
    source = registry_path.read_text()
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "discover_plugins":
            return node
    return None


def _has_signature_validation(node: ast.FunctionDef) -> bool:
    """
    Check if the discover_plugins function validates entry point signatures.

    Looks for:
    - inspect.signature() calls
    - inspect.getfullargspec() calls
    - hasattr() checks for __init__ or __call__
    - __init__ signature validation before instantiation
    """
    source = ast.unparse(node)

    # Check for signature validation patterns
    validation_patterns = [
        "signature",
        "getfullargspec",
        "getargspec",
        "__init__",
        "__call__",
        "getattr",
        "hasattr",
        "inspect",
    ]

    has_any_validation = any(pattern in source for pattern in validation_patterns)

    # Also check for validate() or check_signature() style functions
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Call):
            func_name = ""
            if isinstance(subnode.func, ast.Name):
                func_name = subnode.func.id
            elif isinstance(subnode.func, ast.Attribute):
                func_name = subnode.func.attr

            if func_name and any(
                v in func_name.lower()
                for v in ["validate", "check", "verify", "inspect", "signature"]
            ):
                has_any_validation = True
                break

    return has_any_validation


def _find_instantiation_without_validation(node: ast.FunctionDef) -> list[ast.Call]:
    """
    Find places where attr() is called (class instantiation) without prior
    signature validation of the __init__ method.

    Returns list of Call nodes that represent potentially unsafe instantiation.
    """
    unsafe_calls: list[ast.Call] = []

    # Track variables that have been validated
    validated_vars: set[str] = set()

    for subnode in ast.walk(node):
        # Look for signature validation that sets a variable
        if isinstance(subnode, ast.Assign):
            if isinstance(subnode.value, ast.Call):
                call = subnode.value
                func_name = ""
                if isinstance(call.func, ast.Name):
                    func_name = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr

                if func_name and any(
                    v in func_name.lower() for v in ["signature", "validate", "check", "inspect"]
                ):
                    # Mark targets as validated
                    for target in subnode.targets:
                        if isinstance(target, ast.Name):
                            validated_vars.add(target.id)

        # Look for direct instantiation calls: attr()
        if isinstance(subnode, ast.Call):
            if isinstance(subnode.func, ast.Name) and subnode.func.id == "attr":
                # Check if this attr call is validated by looking at context
                # attr() is called when instantiating plugin classes
                unsafe_calls.append(subnode)

    return unsafe_calls


@pytest.mark.xfail(
    reason="deterministic bug detector for #206 - plugin loader missing signature validation",
    strict=False,
)
def test_plugin_loader_has_entry_point_signature_validation():
    """
    Detect that discover_plugins validates entry point signatures before instantiation.

    Issue #206: Plugin loader imports modules without validating entry point signatures.
    This allows malicious or malformed plugin classes with unexpected __init__
    signatures to be instantiated, potentially causing runtime errors or
    arbitrary code execution.

    Expected: discover_plugins should validate that discovered plugin classes
    have valid __init__ signatures before calling attr() to instantiate them.

    Current: The code finds classes inheriting from ScannerPlugin and directly
    calls attr() (instantiation) without any signature validation.
    """
    node = _get_discover_plugins_ast_node()
    assert node is not None, "discover_plugins function not found in registry.py"

    # Check if the function has any signature validation
    has_validation = _has_signature_validation(node)

    # Find unsafe instantiation calls
    unsafe_calls = _find_instantiation_without_validation(node)

    # The test fails (xfail) if there are unsafe instantiations without validation
    has_unsafe_instantiation = len(unsafe_calls) > 0

    # This assertion will fail (triggering xfail) when:
    # - There are unsafe instantiation calls (attr())
    # - AND there's no signature validation present
    if has_unsafe_instantiation and not has_validation:
        pytest.fail(
            f"BUG DETECTED (#206): discover_plugins has {len(unsafe_calls)} unsafe "
            f"instantiation(s) without entry point signature validation. "
            f"Found attr() calls that instantiate plugin classes without validating "
            f"__init__ signatures first."
        )


@pytest.mark.xfail(
    reason="deterministic bug detector for #240 - missing inspect.signature check", strict=False
)
def test_plugin_loader_inspects_init_signature():
    """
    Detect that the plugin loader uses inspect module to validate __init__ signatures.

    This test specifically checks for inspect.signature() or similar calls
    that would validate the constructor signature before instantiation.
    """
    node = _get_discover_plugins_ast_node()
    assert node is not None, "discover_plugins function not found in registry.py"

    source = ast.unparse(node)

    # Look for inspect.signature or inspect.getfullargspec usage
    uses_inspect = "inspect.signature" in source or "inspect.getfullargspec" in source
    checks_init = "__init__" in source

    # The test passes (no xfail triggered) only if both conditions are met
    if not (uses_inspect and checks_init):
        pytest.fail(
            f"BUG DETECTED (#240): discover_plugins does not use inspect module "
            f"to validate __init__ signatures before instantiation. "
            f"uses_inspect={uses_inspect}, checks_init={checks_init}"
        )


@pytest.mark.xfail(
    reason="deterministic bug detector - validate callables before instantiation", strict=False
)
def test_plugin_loader_validates_callable_signature():
    """
    Detect that the plugin loader validates callables have valid signatures.

    Checks for patterns like:
    - inspect.signature(attr)
    - callable() checks combined with signature validation
    - hasattr checks for required methods
    """
    node = _get_discover_plugins_ast_node()
    assert node is not None, "discover_plugins function not found in registry.py"

    validation_checks = 0

    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Call):
            func_name = ""
            if isinstance(subnode.func, ast.Name):
                func_name = subnode.func.id
            elif isinstance(subnode.func, ast.Attribute):
                func_name = subnode.func.attr

            # Count validation-related calls
            if func_name in ["hasattr", "getattr", "callable"]:
                validation_checks += 1
            if "signature" in func_name.lower():
                validation_checks += 1
            if func_name in ["validate", "check", "verify"]:
                validation_checks += 1

    # Require at least 2 validation checks to be considered safe
    if validation_checks < 2:
        pytest.fail(
            f"BUG DETECTED: discover_plugins has insufficient validation "
            f"({validation_checks} validation checks found, minimum 2 required). "
            f"Plugin loader should validate entry point signatures before instantiation."
        )
