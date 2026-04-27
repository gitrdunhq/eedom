"""Scanner plugin contract.
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/test_plugin_templates.py
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

# Default templates directory — co-located with eedom.templates package.
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class PluginCategory(StrEnum):
    dependency = "dependency"
    code = "code"
    infra = "infra"
    quality = "quality"
    supply_chain = "supply_chain"


@dataclass
class PluginResult:
    plugin_name: str
    findings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""
    package_root: str | None = None
    category: str = ""


class ScannerPlugin(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str: ...

    @property
    @abc.abstractmethod
    def description(self) -> str: ...

    @property
    @abc.abstractmethod
    def category(self) -> PluginCategory: ...

    @property
    def depends_on(self) -> list[str]:
        """Plugin names this plugin must run after.

        Return ``["*"]`` to run after *all* other plugins (policy-plugin
        convention — equivalent to the former hard-coded ``plugin.name == "opa"``
        check in the registry).  Return ``["plugin-a", "plugin-b"]`` to run
        after those specific plugins.  An empty list (the default) imposes no
        ordering constraint.
        """
        return []

    @abc.abstractmethod
    def can_run(self, files: list[str], repo_path: Path) -> bool: ...

    @abc.abstractmethod
    def run(self, files: list[str], repo_path: Path) -> PluginResult: ...

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        """Render plugin result to markdown.

        Looks for ``{template_dir}/{plugin_name}.md.j2``.  If found the
        template is rendered via Jinja2 with the context produced by
        :meth:`_template_context`.  When no template file exists the call
        falls through to :meth:`_render_inline`.
        """
        tdir = template_dir if template_dir is not None else _TEMPLATES_DIR
        template_name = f"{self.name}.md.j2"
        tpath = tdir / template_name
        if tpath.exists():
            from jinja2 import Environment, FileSystemLoader

            env = Environment(
                loader=FileSystemLoader(str(tdir)),
                autoescape=False,
                keep_trailing_newline=True,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            tmpl = env.get_template(template_name)
            ctx = self._template_context(result)
            return tmpl.render(**ctx)
        return self._render_inline(result)

    def _template_context(self, result: PluginResult) -> dict:
        """Return the Jinja2 template variable dict.

        Override in subclasses to inject plugin-specific pre-processed data
        (e.g. grouped findings, computed totals) alongside the base keys.
        """
        return {
            "result": result,
            "findings": result.findings,
            "summary": result.summary,
            "error": result.error,
            "plugin_name": result.plugin_name,
        }

    def _render_inline(self, result: PluginResult) -> str:
        """Inline fallback renderer used when no template file is found.

        Subclasses that ship Jinja2 templates rename their old ``render()``
        body to this method so it still serves as a fallback during development
        and testing.  Plugins without templates continue to override
        :meth:`render` directly.
        """
        return ""
