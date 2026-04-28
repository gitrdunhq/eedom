# CLAUDE.md

This file provides guidance to Claude Code when working with the eedom scanner.

## What This Is

Eagle Eyed Dom — fully deterministic dependency and code review for CI. 18 plugins, 33 custom semgrep rules, 12 code graph checks, 6 OPA policy rules, 600+ tests, zero LLM in the decision path.

## Commands

```bash
uv sync --group dev                    # Install all deps
make test                              # Run tests in container (podman/docker)
make test-host                         # Run tests on host (escape hatch)
uv run ruff check src/ tests/          # Lint
uv run black src/ tests/               # Format
make quality-check                     # Format + lint
make dogfood                           # Self-scan with eedom review
make preflight                         # Format + lint + test + dogfood
opa test policies/                     # OPA Rego policy tests
```

**Tests MUST run in a container.** `make test` handles this automatically. Bare `uv run pytest` will abort with an error unless `EEDOM_ALLOW_HOST_TESTS=1` is set.

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
- `src/eedom/plugins/` — 18 scanner plugins with auto-discovery via `PluginRegistry`.
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

6 rules in `policies/policy.rego`. Critical/high vulns deny. Forbidden licenses deny. Package age < 30 days denies. Malicious packages deny. Medium vulns warn. High transitive dep count warns.

## Dev Ports

Port range 12000-13000 only. Never use common ports.
- PostgreSQL: 12432

## Testing

Every source file has a `# tested-by: tests/unit/test_X.py` comment. TDD red-green is mandatory. Hypothesis property-based tests cover boundary invariants.

### Property-Based Testing (DPS-12)

Code at security, cryptographic, state, or trust boundaries requires formal property domain mapping. Each test maps to a named domain and formal property type: SAFETY (bad thing never happens), LIVENESS (good thing eventually happens), INVARIANT (always true), PERFORMANCE (within bounds).

**Core domains** (security/crypto):

| Domain | Type | Property |
|--------|------|----------|
| Integrity | SAFETY | Tampering never succeeds |
| Confidentiality | SAFETY | Secrets never leak to output |
| Determinism | INVARIANT | Same inputs → same output |
| Uniqueness | INVARIANT | Different inputs → different outputs |
| Availability | LIVENESS | Valid operations eventually succeed |

**Stateful domains** (state machines, workflows, pipelines):

| Domain | Type | Property |
|--------|------|----------|
| Non-repudiation | INVARIANT | Proof of action always exists once created |
| Idempotency | INVARIANT | Repeat always produces same result |
| Atomicity | SAFETY | Partial state never visible |
| Monotonicity | SAFETY | State never moves backward |

**System domains** (concurrency, resources, lifecycle):

| Domain | Type | Property |
|--------|------|----------|
| Ordering | SAFETY | Out-of-sequence never happens |
| Isolation | SAFETY | Parallel ops never interfere |
| Boundedness | PERFORMANCE | Resources stay within finite limits |
| Linearity | SAFETY | Token/resource never consumed twice |
| Reversibility | LIVENESS | Failed operations eventually clean up |

Not every module needs all 14. Pick the domains that match your boundary. Group property tests in a `TestProperties` class. If you can't state the domain and property type, the test is incomplete.

## Capability Matrix

`docs/CAPABILITIES.md` is the canonical feature inventory — optimized for LLM ingestion and human comparison. **Update it whenever you add, remove, or modify**: a plugin, semgrep rule, code graph check, OPA policy rule, CLI command, output format, or integration. Keep counts accurate. Update the LAST VERIFIED date.

## Commit Message Discipline

release-please uses conventional commit prefixes for semver bumps. Be conservative:

- `feat:` → **minor** bump (0.x.0) — new user-facing capabilities only
- `fix:` → **patch** bump (0.0.x) — bug fixes, config fixes, CI fixes, behavior corrections
- `chore:` → **no bump** — docs, refactors, test-only changes, housekeeping, dependency updates

Do NOT use `feat:` for config tweaks, CI fixes, or internal refactors. If it doesn't change what a user sees or does, it's `fix:` or `chore:`.

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
