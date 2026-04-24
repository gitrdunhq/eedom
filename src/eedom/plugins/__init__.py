"""Eagle Eyed Dom scanner plugins.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.core.registry import PluginRegistry, discover_plugins

__all__ = ["PluginRegistry", "discover_plugins", "get_default_registry"]


def get_default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    plugin_dir = Path(__file__).parent
    for plugin in discover_plugins(plugin_dir):
        registry.register(plugin)
    return registry
