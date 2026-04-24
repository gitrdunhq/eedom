"""Plugin registry — discovery, filtering, execution.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from eedom.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
)

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


def _topological_sort(plugins: list[ScannerPlugin]) -> list[ScannerPlugin]:
    """Return *plugins* sorted so every dependency runs before its dependent.

    Ignores dependencies on plugin names that are not in the current list
    (unknown deps are silently skipped — no error).  Raises ``ValueError``
    on circular dependencies.
    """
    if not plugins:
        return []

    by_name = {p.name: p for p in plugins}

    # Build a graph: each plugin -> set of plugins it must run *after*
    graph: dict[str, set[str]] = {}
    for p in plugins:
        # Only count deps that are actually registered; drop unknown names
        known_deps = {d for d in p.depends_on if d in by_name}
        graph[p.name] = known_deps

    try:
        sorter = TopologicalSorter(graph)
        return [by_name[name] for name in sorter.static_order()]
    except CycleError as exc:
        raise ValueError(f"Circular plugin dependency detected: {exc}") from exc


def _is_under(file_path: str, root: Path) -> bool:
    """Return True when *file_path* is a descendant of *root*."""
    try:
        return Path(file_path).is_relative_to(root)
    except ValueError:
        return False


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ScannerPlugin | None:
        return self._plugins.get(name)

    def list(
        self,
        category: PluginCategory | None = None,
        names: list[str] | None = None,
    ) -> list[ScannerPlugin]:
        plugins = list(self._plugins.values())
        if category is not None:
            plugins = [p for p in plugins if p.category == category]
        if names is not None:
            name_set = set(names)
            plugins = [p for p in plugins if p.name in name_set]
        return plugins

    def run_all(
        self,
        files: list[str],
        repo_path: Path,
        names: list[str] | None = None,
        categories: list[PluginCategory] | None = None,
        disabled_names: set[str] | list[str] | None = None,
        enabled_names: set[str] | list[str] | None = None,
        package_units: list | None = None,
    ) -> list[PluginResult]:
        """Run all matching plugins.

        Filtering priority:
        1. *names* / *categories* — existing positional filters applied first.
        2. *disabled_names* — plugins in this set are skipped.
        3. *enabled_names* — plugins in this set override disabled_names.
           A plugin that is both disabled and enabled will run.
           enabled_names alone (without any disabled_names) has no filtering effect.

        When *package_units* is provided (a list of
        ``eedom.core.manifest_discovery.PackageUnit``), each plugin is executed
        once per package.  Files are scoped to the package root and results are
        tagged with ``PluginResult.package_root``.  OPA (policy) plugins receive
        only per-package findings, not the global merged list.  When
        *package_units* is ``None`` the existing single-pass behaviour is used
        unchanged.
        """
        disabled_set: set[str] = set(disabled_names) if disabled_names else set()
        enabled_set: set[str] = set(enabled_names) if enabled_names else set()

        scan_plugins = []
        policy_plugins = []
        for plugin in self._plugins.values():
            if names and plugin.name not in names:
                continue
            if categories and plugin.category not in categories:
                continue
            if plugin.name in disabled_set and plugin.name not in enabled_set:
                continue
            # depends_on=["*"] marks a policy plugin (run after all scan plugins
            # and receive merged findings).  Replaces the former hard-coded
            # ``plugin.name == "opa"`` check.
            if "*" in plugin.depends_on:
                policy_plugins.append(plugin)
            else:
                scan_plugins.append(plugin)

        # Topologically sort scan plugins so each depends_on constraint is honoured.
        # Raises ValueError on circular dependencies.
        scan_plugins = _topological_sort(scan_plugins)

        if package_units is not None:
            return self._run_all_per_package(
                files, repo_path, scan_plugins, policy_plugins, package_units
            )

        results: list[PluginResult] = []
        for plugin in scan_plugins:
            results.append(self._run_one(plugin, files, repo_path))

        if policy_plugins:
            all_findings: list[dict] = []
            for r in results:
                if not r.error:
                    all_findings.extend(r.findings)
            for plugin in policy_plugins:
                results.append(self._run_policy(plugin, files, repo_path, all_findings))

        return results

    def _run_all_per_package(
        self,
        files: list[str],
        repo_path: Path,
        scan_plugins: list[ScannerPlugin],
        policy_plugins: list[ScannerPlugin],
        package_units: list,
    ) -> list[PluginResult]:
        """Execute plugins once per PackageUnit, scoping files to each package root."""
        results: list[PluginResult] = []
        for unit in package_units:
            unit_root = unit.root
            pkg_root_str = str(unit_root)
            unit_files = [f for f in files if _is_under(f, unit_root)]

            unit_scan_results: list[PluginResult] = []
            for plugin in scan_plugins:
                r = self._run_one(plugin, unit_files, repo_path)
                r.package_root = pkg_root_str
                unit_scan_results.append(r)

            if policy_plugins:
                unit_findings: list[dict] = []
                for r in unit_scan_results:
                    if not r.error:
                        unit_findings.extend(r.findings)
                for plugin in policy_plugins:
                    r = self._run_policy(plugin, unit_files, repo_path, unit_findings)
                    r.package_root = pkg_root_str
                    unit_scan_results.append(r)

            results.extend(unit_scan_results)
        return results

    def _run_policy(
        self,
        plugin: ScannerPlugin,
        files: list[str],
        repo_path: Path,
        findings: list[dict],
    ) -> PluginResult:
        if not plugin.can_run(files, repo_path):
            return PluginResult(
                plugin_name=plugin.name,
                summary={"status": "skipped"},
            )
        try:
            return plugin.run(files, repo_path, findings=findings)
        except Exception as exc:
            logger.warning(
                "plugin.policy_failed",
                plugin=plugin.name,
                error=str(exc),
            )
            return PluginResult(plugin_name=plugin.name, error=str(exc))

    def _run_one(
        self,
        plugin: ScannerPlugin,
        files: list[str],
        repo_path: Path,
    ) -> PluginResult:
        if not plugin.can_run(files, repo_path):
            return PluginResult(
                plugin_name=plugin.name,
                summary={"status": "skipped"},
            )
        try:
            return plugin.run(files, repo_path)
        except Exception as exc:
            logger.warning(
                "plugin.run_failed",
                plugin=plugin.name,
                error=str(exc),
            )
            return PluginResult(plugin_name=plugin.name, error=str(exc))


def discover_plugins(plugin_dir: Path) -> list[ScannerPlugin]:
    plugins: list[ScannerPlugin] = []
    if not plugin_dir.is_dir():
        return plugins
    for path in sorted(plugin_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = f"eedom.plugins.{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(
                module_name,
                path,
            )
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, ScannerPlugin)
                    and attr is not ScannerPlugin
                ):
                    plugins.append(attr())
        except Exception as exc:
            logger.warning(
                "plugin.discovery_failed",
                path=str(path),
                error=str(exc),
            )
    return plugins
