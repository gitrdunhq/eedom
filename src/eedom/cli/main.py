"""CLI entry point for the Review pipeline."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from pathlib import Path

import click
import structlog

from eedom.core.models import OperatingMode
from eedom.plugins import get_default_registry

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Watch-mode constants
# ---------------------------------------------------------------------------
_WATCH_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".ts", ".js", ".tf", ".yaml", ".yml", ".json"}
)
_IGNORE_DIRS: frozenset[str] = frozenset({"__pycache__", ".git", ".eedom", ".dogfood"})


class DebounceTimer:
    """Fires a callback once after a quiet period, resetting on each new event.

    Calling reset() cancels any in-flight timer and starts a fresh one.
    The callback fires only after `delay` seconds of inactivity.
    """

    def __init__(self, delay: float, callback: Callable[[], None]) -> None:
        self._delay = delay
        self._callback = callback
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def reset(self) -> None:
        """Schedule (or reschedule) the callback after the debounce delay."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._delay, self._callback)
            self._timer.daemon = True
            self._timer.start()

    def cancel(self) -> None:
        """Cancel any pending callback."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


def _check_isolated_environment() -> None:
    """Abort if running outside a virtual environment or container."""
    in_venv = sys.prefix != sys.base_prefix
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    bypass = "EEDOM_ALLOW_GLOBAL" in __import__("os").environ
    if not in_venv and not in_container and not bypass:
        click.echo(
            "ERROR: eedom must run in an isolated environment.\n"
            "\n"
            "  uvx eedom review --all              # recommended\n"
            "  pipx install eedom                   # persistent CLI\n"
            "  pip install eedom  (inside a venv)   # manual venv\n"
            "  docker run eedom                     # container\n"
            "\n"
            "Set EEDOM_ALLOW_GLOBAL=1 to override (not recommended).",
            err=True,
        )
        raise SystemExit(1)


@click.group()
@click.version_option(package_name="eedom")
def cli() -> None:
    """Eagle Eyed Dom — fully deterministic dependency and code review for CI."""
    _check_isolated_environment()


def _register_subcommands() -> None:
    from eedom.cli.inspect_cmds import check_health, healthcheck, plugins
    from eedom.cli.query_cmd import query

    cli.add_command(healthcheck)
    cli.add_command(check_health)
    cli.add_command(plugins)
    cli.add_command(query)


_register_subcommands()


@cli.command()
@click.option(
    "--repo-path", required=True, type=click.Path(exists=False), help="Path to the repository root."
)
@click.option("--diff", required=True, type=str, help="Path to diff file, or '-' for stdin.")
@click.option("--pr-url", required=True, type=str, help="PR URL for context and comments.")
@click.option("--team", required=True, type=str, help="Team name submitting the request.")
@click.option(
    "--operating-mode",
    required=True,
    type=click.Choice(["monitor", "advise"]),
    help="Operating mode.",
)
@click.option(
    "--output-json",
    type=click.Path(),
    default=None,
    help="Write machine-readable decision JSON to this path.",
)
def evaluate(
    repo_path: str,
    diff: str,
    pr_url: str,
    team: str,
    operating_mode: str,
    output_json: str | None,
) -> None:
    """Run the full review pipeline on dependency changes."""
    diff_text = _read_diff(diff)
    mode = OperatingMode(operating_mode)

    try:
        from eedom.core.config import EedomSettings

        config = EedomSettings()  # type: ignore[call-arg]
    except Exception:
        logger.warning(
            "config_load_failed", msg="Pipeline skipped — config unavailable (fail-open)"
        )
        click.echo("Pipeline skipped — configuration unavailable (fail-open).", err=True)
        sys.exit(0)

    try:
        import orjson

        from eedom.core.bootstrap import bootstrap as _bootstrap
        from eedom.core.pipeline import ReviewPipeline

        _context = _bootstrap(config)
        pipeline = ReviewPipeline(config, context=_context)
        decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=mode,
            repo_path=Path(repo_path),
        )

        if not decisions:
            click.echo("No dependency changes detected.")
            sys.exit(0)

        for decision in decisions:
            click.echo(decision.memo_text or "")

        if output_json and decisions:
            last = decisions[-1]
            Path(output_json).write_bytes(
                orjson.dumps(last.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
            )

        sys.exit(0)

    except Exception:
        logger.exception("pipeline_failed_unexpectedly")
        sys.exit(1)


@cli.command()
@click.option("--diff", type=str, default=None, help="Path to diff file.")
@click.option("--repo-path", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option("--scanners", type=str, default=None, help="Comma-separated plugin names.")
@click.option("--category", type=str, default=None, help="Comma-separated categories.")
@click.option("--all", "run_all", is_flag=True, help="Run all plugins.")
@click.option("--output", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "sarif", "json"]),
    default="markdown",
    help="Output format.",
)
@click.option(
    "--sarif-max-findings",
    type=int,
    default=1000,
    help="Max findings per plugin in SARIF output. 0 for no limit.",
)
@click.option("--pr-url", type=str, default="", help="PR URL for comment header.")
@click.option("--pr-num", type=int, default=0, help="PR number.")
@click.option("--title", type=str, default="PR Review", help="PR title.")
@click.option(
    "--watch",
    is_flag=True,
    help="Watch for file changes and re-run review (debounced 500 ms).",
)
@click.option(
    "--disable",
    type=str,
    default="",
    help="Comma-separated plugin names to disable.",
)
@click.option(
    "--enable",
    type=str,
    default="",
    help="Comma-separated plugin names to force-enable (overrides --disable).",
)
@click.option(
    "--package",
    type=click.Path(),
    default=None,
    help="Scan only this package directory.",
)
@click.option(
    "--pr",
    type=click.IntRange(min=1),
    default=None,
    help="Post findings as inline PR review comments via GitHub API. Requires gh CLI.",
)
@click.option(
    "--repo",
    "gh_repo",
    type=str,
    default=None,
    help="GitHub repo (owner/name) for --pr mode. Auto-detected if omitted.",
)
def review(
    diff: str | None,
    repo_path: str,
    scanners: str | None,
    category: str | None,
    run_all: bool,
    output: str | None,
    output_format: str,
    sarif_max_findings: int,
    pr_url: str,
    pr_num: int,
    title: str,
    watch: bool,
    disable: str,
    enable: str,
    package: str | None,
    pr: int | None,
    gh_repo: str | None,
) -> None:
    """Run Eagle Eyed Dom plugin review on a repo or diff."""
    from eedom.core.bootstrap import bootstrap_review
    from eedom.core.plugin import PluginCategory
    from eedom.core.renderer import render_comment
    from eedom.core.repo_config import RepoConfig, load_repo_config

    _ctx = bootstrap_review(registry_factory=get_default_registry)
    registry = _ctx.analyzer_registry
    repo = Path(repo_path)
    names = scanners.split(",") if scanners else None
    cats = [PluginCategory(c.strip()) for c in category.split(",")] if category else None
    plugin_map = {p.name: p for p in registry.list()}
    repo_name = pr_url.split("github.com/")[-1].split("/pull")[0] if "github.com" in pr_url else ""

    repo_config = (
        load_repo_config(repo) if (repo / ".eagle-eyed-dom.yaml").exists() else RepoConfig()
    )
    disabled_names: set[str] = set(repo_config.plugins.disabled or [])
    if disable:
        for _d in disable.split(","):
            disabled_names.add(_d.strip())
    disabled_names.discard("")
    enabled_names: set[str] = set(repo_config.plugins.enabled or [])
    if enable:
        for _e in enable.split(","):
            enabled_names.add(_e.strip())
    enabled_names.discard("")

    def _build_file_list() -> list[str]:
        from eedom.core.ignore import load_ignore_patterns, should_ignore

        ignore_patterns = load_ignore_patterns(repo)

        if diff:
            diff_text = _read_diff(diff)
            files: list[str] = []
            for line in diff_text.split("\n"):
                if line.startswith("diff --git"):
                    parts = line.split(" b/")
                    if len(parts) == 2:
                        fpath = parts[1].strip()
                        full = repo / fpath
                        if (full.exists() or not fpath.startswith(".git")) and not should_ignore(
                            fpath, ignore_patterns
                        ):
                            files.append(str(full))
            return files
        files = []
        for ext in ("*.py", "*.ts", "*.js", "*.tf", "*.yaml", "*.yml", "*.json"):
            files.extend(
                str(p)
                for p in repo.rglob(ext)
                if not should_ignore(str(p.relative_to(repo)), ignore_patterns)
            )
        return files

    def run_review() -> None:
        from eedom.core.use_cases import ReviewOptions, review_repository

        files = _build_file_list()

        options = ReviewOptions(
            scanners=names,
            categories=cats,
            disabled=disabled_names,
            enabled=enabled_names,
        )
        review_result = review_repository(_ctx, files, repo, options)
        results = review_result.results

        if output_format == "sarif" or pr is not None:
            import orjson

            from eedom.core.sarif import to_sarif

            sarif_doc = to_sarif(
                results, repo_path=str(repo), max_findings_per_run=sarif_max_findings
            )

            if pr is not None:
                from eedom.core.pr_review import (
                    detect_gh_repo,
                    get_pr_diff_files,
                    post_review,
                    sarif_to_review,
                )

                target_repo = gh_repo or detect_gh_repo()
                if not target_repo:
                    click.echo("Could not detect GitHub repo. Use --repo owner/name.", err=True)
                    sys.exit(1)

                try:
                    diff_files = get_pr_diff_files(target_repo, pr)
                except RuntimeError as exc:
                    click.echo(str(exc), err=True)
                    sys.exit(1)
                pr_review = sarif_to_review(sarif_doc, diff_files)
                ok = post_review(target_repo, pr, pr_review)
                click.echo(
                    f"{'Posted' if ok else 'Failed to post'} review on PR #{pr}: "
                    f"{pr_review.event} ({len(pr_review.comments)} inline, "
                    f"{len(pr_review.outside_diff)} outside diff)"
                )
                if not ok:
                    sys.exit(1)
                return

            sarif_text = orjson.dumps(sarif_doc, option=orjson.OPT_INDENT_2).decode()
            if output:
                Path(output).write_text(sarif_text)
                click.echo(f"SARIF written to {output}")
            else:
                click.echo(sarif_text)
            return

        if output_format == "json":
            from eedom.core.json_report import render_json

            json_text = render_json(results, repo=repo_name or str(repo))
            if output:
                Path(output).write_text(json_text)
                click.echo(f"JSON written to {output}")
            else:
                click.echo(json_text)
            return

        md = render_comment(
            results,
            repo=repo_name or str(repo),
            pr_num=pr_num,
            title=title,
            file_count=len(files),
            plugin_renderers=plugin_map,
        )
        if output:
            Path(output).write_text(md)
            click.echo(f"Review written to {output} ({len(md)} chars)")
        else:
            click.echo(md)

    run_review()

    if watch:
        _watch_and_rerun(repo_path=repo, run_review=run_review)


def _read_diff(diff_path: str) -> str:
    if diff_path == "-":
        return sys.stdin.read()
    path = Path(diff_path)
    if not path.exists():
        logger.warning("diff_file_not_found", path=diff_path)
        return ""
    return path.read_text()


def _watch_and_rerun(repo_path: Path, run_review: Callable[[], None]) -> None:
    """Start a watchdog observer and re-run review on relevant file changes.

    Debounces events by 500 ms so rapid saves trigger only one re-run.
    Exits cleanly on Ctrl+C with no stack trace.
    """
    try:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        click.echo("watchdog is required for --watch mode. Install with: uv add watchdog", err=True)
        return

    debounce = DebounceTimer(delay=0.5, callback=run_review)

    class _Handler(FileSystemEventHandler):
        def on_any_event(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            path = Path(str(event.src_path))
            if path.suffix not in _WATCH_EXTENSIONS:
                return
            for part in path.parts:
                if part in _IGNORE_DIRS:
                    return
            debounce.reset()

    observer = Observer()
    observer.schedule(_Handler(), str(repo_path), recursive=True)
    observer.start()

    click.echo(f"\nWatching {repo_path} for changes (Ctrl+C to exit)…")
    try:
        while observer.is_alive():
            observer.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        debounce.cancel()
        observer.stop()


if __name__ == "__main__":
    cli()
