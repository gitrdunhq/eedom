# CLAUDE.md

This file provides guidance to Claude Code when working with the eedom scanner.

## What This Is

Eagle Eyed Dom — fully deterministic dependency and code review for CI. 15 plugins, 600+ tests, zero LLM in the decision path.

## Commands

```bash
uv sync --group dev                    # Install all deps
uv run pytest tests/ -v                # Run all tests
uv run pytest tests/unit/test_X.py -v  # Run one test file
uv run ruff check src/ tests/          # Lint
uv run black src/ tests/               # Format
make quality-check                     # Format + lint
make test                              # Run tests
make dogfood                           # Self-scan with eedom review
make preflight                         # Format + lint + test + dogfood
opa test policies/                     # OPA Rego policy tests
```

Container:
```bash
podman build -t eedom:latest .
podman run --rm -v /path/to/repo:/workspace:ro eedom:latest \
  review --repo-path /workspace --all
```

## Architecture

Three-tier — imports flow downward only (cli -> core -> data):

- `src/eedom/cli/` — thin CLI adapter. Parses args, delegates to core, formats output.
- `src/eedom/core/` — all business logic. Pipeline, policy, plugin registry, renderer, SARIF, config.
- `src/eedom/data/` — persistence and external calls. Scanners, DB, evidence, parquet, PyPI client.
- `src/eedom/plugins/` — 15 scanner plugins with auto-discovery via `PluginRegistry`.
- `src/eedom/agent/` — GATEKEEPER Copilot Agent (second presentation-tier entry point).
- `src/eedom/templates/` — Jinja2 templates for PR comment rendering.

## Critical Design Rules

**Fail-open**: No scanner failure blocks a build. Every external call has a timeout. Every failure returns a typed result.

**Timeouts**: scanner=60s, combined=180s, OPA=10s, LLM=30s, pipeline=300s. All from config.

**OPA input uses `input.pkg` not `input.package`**: `package` is reserved in Rego v1.

**Evidence keyed by commit SHA + timestamp**: sealed with SHA-256 chain.

**Operating modes**: `monitor` (log only) and `advise` (PR comment + build UNSTABLE on reject).

**Scanner disagreement**: highest severity wins during dedup in `core/normalizer.py`.

**Plugin dependency graph**: plugins declare `depends_on` for topological execution order.

## OPA Policy

6 rules in `policies/admission.rego`. Critical/high vulns deny. Forbidden licenses deny. Package age < 30 days denies. Malicious packages deny. Medium vulns warn. High transitive dep count warns.

## Dev Ports

Port range 12000-13000 only. Never use common ports.
- PostgreSQL: 12432

## Testing

Every source file has a `# tested-by: tests/unit/test_X.py` comment. TDD red-green is mandatory. Hypothesis property-based tests cover boundary invariants.

## Code Conventions

- structlog for logging, never print()
- Enums for all state fields, never raw strings
- Typed Pydantic models at every boundary
- `# tested-by:` annotation on every source file

## GATEKEEPER Copilot Agent

The `agent/` module is a presentation-tier entry point parallel to `cli/`. It wraps the same pipeline as a GitHub Copilot Extension for reactive PR review.

- Entry point: `python -m eedom.agent.main`
- Config: `GATEKEEPER_*` env vars
- Tools: `evaluate_change`, `check_package`, `scan_code`
- ADRs: `docs/adr/001-004`
