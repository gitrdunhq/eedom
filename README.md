<div align="center">
  <img src="assets/hero.svg" alt="Eagle Eyed Dom" width="900">
  <br>
  <strong>Fully deterministic dependency review for CI.</strong><br>
  15 plugins. 6 OPA policy rules. 18 ecosystems. Zero LLM in the decision path.
  <br><br>

  <a href="#quick-start"><img src="https://img.shields.io/badge/get_started-→-d4251a?style=flat-square" alt="Get Started"></a>
  <a href="#the-15-plugins"><img src="https://img.shields.io/badge/15_plugins-deterministic-f2c14a?style=flat-square&labelColor=0e0706" alt="15 Plugins"></a>
  <a href="#opa-policy-rules"><img src="https://img.shields.io/badge/OPA-6_rules-1e3a8a?style=flat-square" alt="OPA Rules"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm_Shield-7ae582?style=flat-square" alt="PolyForm Shield License"></a>
</div>

<br>

---

When a PR touches a dependency manifest — `requirements.txt`, `package.json`, `Cargo.toml`, `go.mod`, any of 18 ecosystems — Eagle Eyed Dom detects the changed packages, runs 15 plugins in parallel, deduplicates findings, evaluates them against OPA policy, writes tamper-evident evidence, and appends the decision to a Parquet audit log.

Every scanning tool is deterministic. The decision is deterministic. Nothing blocks the build unless OPA says so.

**Two entry points, same pipeline:**

| Entry Point | Interface | Use Case |
|-------------|-----------|----------|
| **CLI** | `eedom evaluate` / `eedom review` | CI pipelines, local dev |
| **GATEKEEPER** | `python -m eedom.agent.main` | GitHub Copilot Agent for reactive PR review |

---

## The 15 Plugins

<div align="center">
  <img src="assets/scanners.svg" alt="Scanner lineup" width="700">
</div>

<br>

All deterministic. Zero LLM. The only AI is the optional Copilot agent wrapper that synthesizes results into PR comments — and even that is pluggable and removable.

### Dependency (run on every evaluation)

| # | Plugin | What it does |
|---|--------|-------------|
| 1 | **Syft** | SBOM generation (CycloneDX, 18 ecosystems) |
| 2 | **OSV-Scanner** | Known vulnerability database (CVE/GHSA) |
| 3 | **Trivy** | Vulnerability scanning |
| 4 | **ScanCode** | License detection (SPDX) |
| 5 | **OPA** | Policy enforcement (6 Rego rules) — see [policy rules](#opa-policy-rules) |

### Code Analysis (run on changed source files)

| # | Plugin | What it does |
|---|--------|-------------|
| 6 | **Semgrep** | AST pattern matching (dynamic rulesets + custom org rules) |
| 7 | **PMD CPD** | Copy-paste detection (12 languages) |

### Infrastructure

| # | Plugin | What it does |
|---|--------|-------------|
| 8 | **kube-linter** | K8s/Helm security validation |

### Quality

| # | Plugin | What it does |
|---|--------|-------------|
| 9 | **Lizard + Radon** | Cyclomatic complexity + maintainability index |
| 10 | **cspell** | Code-aware spell checking (en-CA, 15 dictionaries) |
| 11 | **ls-lint** | File naming conventions |
| 12 | **Blast Radius** | AST→SQLite code graph, 8+ SQL checks |

### Supply Chain

| # | Plugin | What it does |
|---|--------|-------------|
| 13 | **Supply Chain** | Unpinned deps + lockfile integrity + latest tag detection |
| 14 | **ClamAV** | Malware/virus scanning |
| 15 | **Gitleaks** | Secret/credential detection (800+ patterns) |

**Scanner disagreement:** When OSV-Scanner and Trivy report the same CVE, the normalizer deduplicates on `(advisory_id, category, package_name, version)`. Highest severity wins.

**Plugin execution order:** Plugins can declare `depends_on` to express ordering constraints. The registry performs a topological sort before execution — OPA, for example, always runs after all scanner plugins have produced findings. Circular dependencies are detected at registry initialization and raise an error before any scan begins.

---

## Quick Start

### Review a repo (native)

```bash
uv sync --group dev

# Review all files in the current repo
uv run eedom review --repo-path . --all

# Review only code analysis plugins
uv run eedom review --repo-path . --category code

# List available plugins
uv run eedom plugins
```

### Full pipeline evaluation (native)

```bash
uv run python -m eedom.cli.main check-health
uv run python -m eedom.cli.main evaluate \
  --repo-path . --diff changes.diff \
  --pr-url "https://github.com/org/repo/pull/1" \
  --team myteam --operating-mode advise
```

### Run via container

```bash
podman build -t eagle-eyed-dom:latest .

git diff origin/main...HEAD > changes.diff

podman run --rm -v "$(pwd):/workspace:ro" eagle-eyed-dom:latest \
  uv run python -m eedom.cli.main evaluate \
    --repo-path /workspace --diff /workspace/changes.diff \
    --pr-url "https://github.com/org/repo/pull/1" \
    --team myteam --operating-mode monitor
```

### GATEKEEPER (GitHub Copilot Agent)

```bash
export GATEKEEPER_GITHUB_TOKEN="ghp_..."
export GATEKEEPER_PR_NUMBER=123
export GATEKEEPER_DIFF_PATH=./changes.diff
export GATEKEEPER_REPO_OWNER=myorg
export GATEKEEPER_REPO_NAME=myrepo

uv run python -m eedom.agent.main
```

---

## Enforcement Modes

| Mode | PR Comment | Build Status | Use Case |
|------|-----------|-------------|----------|
| `block` | Yes | **Fails** on reject | Production gate |
| `warn` | Yes | Always passes | Advisory (default) |
| `log` | No | Always passes | Silent monitoring |

---

## GitHub Action

Install `.github/workflows/gatekeeper.yml` — triggers on PRs that change dependency manifests or source files across 10 ecosystems.

```yaml
name: Eagle Eyed Dom
on:
  pull_request:
    paths:
      - 'requirements*.txt'
      - 'pyproject.toml'
      - 'package.json'
      - 'package-lock.json'
      - 'Cargo.toml'
      - 'Cargo.lock'
      - 'go.mod'
      - 'go.sum'
      - '**/*.py'
      - '**/*.ts'
      - '**/*.go'

jobs:
  review:
    runs-on: self-hosted
    timeout-minutes: 10
    container:
      image: eagle-eyed-dom:latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: git diff ${{ github.event.pull_request.base.sha }}...${{ github.event.pull_request.head.sha }} > .temp/pr.diff
      - run: uv run python -m eedom.agent.main
        env:
          GATEKEEPER_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GATEKEEPER_ENFORCEMENT_MODE: warn
          GATEKEEPER_DIFF_PATH: .temp/pr.diff
          GATEKEEPER_PR_NUMBER: ${{ github.event.pull_request.number }}
          GATEKEEPER_REPO_OWNER: ${{ github.repository_owner }}
          GATEKEEPER_REPO_NAME: ${{ github.event.repository.name }}
```

Or use the composite action (`action.yml`):

```yaml
- uses: org/eagle-eyed-dom@main
  with:
    operating-mode: advise
    team: platform
```

---

## OPA Policy Rules

6 rules in `policies/admission.rego`. All individually toggleable via `input.config.rules_enabled`.

| Rule | Type | Trigger | Default |
|------|------|---------|---------|
| `critical_vuln` | **deny** | Severity in {critical, high} | Always on |
| `forbidden_license` | **deny** | License in forbidden list | GPL-3.0, AGPL-3.0, SSPL-1.0 |
| `package_age` | **deny** | First published < N days ago | 30 days |
| `malicious_package` | **deny** | Advisory ID starts with `MAL-` | Always on |
| `medium_vuln` | warn | Severity = medium | Always on |
| `transitive_count` | warn | Transitive deps > threshold | 200 |

**Decision logic:**

```
deny non-empty        → "reject"
warn only (no deny)   → "approve_with_constraints"
both empty            → "approve"
OPA unavailable       → "needs_review"
```

```bash
opa test policies/   # 16 tests covering every rule and toggle
```

---

## Architecture

```
src/eedom/
├── cli/                    # Presentation: Click CLI (150 lines)
├── agent/                  # Presentation: Eagle Eyed Dom Copilot Agent
│   ├── main.py             #   Agent orchestrator + enforcement
│   ├── tools.py            #   6 @tool functions for the LLM
│   ├── tool_helpers.py     #   Subprocess runners (Semgrep, CPD, kube-linter, lizard)
│   ├── config.py           #   GATEKEEPER_* env vars
│   └── prompt.py           #   System prompt with 8-dimension rubric
├── core/                   # Logic: all business rules
│   ├── pipeline.py         #   Main orchestrator — evaluate() and evaluate_sbom()
│   ├── plugin.py           #   ScannerPlugin ABC + PluginCategory enum
│   ├── registry.py         #   PluginRegistry — auto-discovery + filtering
│   ├── renderer.py         #   Jinja2 comment renderer + severity rollup
│   ├── sarif.py            #   SARIF v2.1.0 output converter
│   ├── repo_config.py      #   .eagle-eyed-dom.yaml loader
│   ├── models.py           #   All Pydantic models and StrEnums
│   ├── policy.py           #   OPA subprocess wrapper
│   ├── diff.py             #   Text diff parser (requirements.txt, pyproject.toml)
│   ├── sbom_diff.py        #   CycloneDX SBOM differ (18 ecosystems via purl)
│   ├── normalizer.py       #   Finding deduplication (highest severity wins)
│   ├── orchestrator.py     #   Parallel scanner runner (ThreadPoolExecutor)
│   ├── decision.py         #   Pure assembler — OPA verdict → AdmissionDecision
│   ├── memo.py             #   Markdown PR comment generator
│   ├── seal.py             #   SHA-256 evidence chain
│   └── taskfit*.py         #   Optional LLM advisory (disabled by default)
├── plugins/                # 15 scanner plugin implementations
│   ├── blast_radius.py     #   AST→SQLite code graph + SQL checks
│   ├── semgrep.py          #   AST pattern matching
│   ├── clamav.py           #   Malware/virus scanning
│   ├── gitleaks.py         #   Secret detection (800+ patterns)
│   └── ...                 #   + 11 more (one file per plugin)
├── templates/              # Jinja2 templates for PR comments
│   ├── comment.md.j2       #   Main comment wrapper (verdict + sections)
│   └── *.md.j2             #   Per-plugin section templates
└── data/                   # Data: scanners, DB, external clients
    ├── scanners/           #   Legacy Scanner ABC + subprocess wrappers
    ├── db.py               #   PostgreSQL + NullRepository fallback
    ├── evidence.py         #   Atomic file-based artifact store
    ├── pypi.py             #   PyPI JSON API client
    ├── parquet_writer.py   #   Append-only Parquet audit log
    ├── catalog.py          #   Org-wide package catalog (pgvector)
    └── alternatives.py     #   Approved alternatives catalog
```

**Three-tier, imports flow downward only.** Presentation → Logic → Data. No exceptions.

---

## Evidence & Audit Trail

Every run writes tamper-evident artifacts:

```
evidence/
  {sha}/{timestamp}/
    {package}/decision.json    # Full typed decision
    {package}/memo.md          # PR comment markdown
    seal.json                  # SHA-256 hash chain
  decisions.parquet            # Append-only audit lake
```

**Atomic writes** — temp file → fsync → rename. Path traversal blocked.

**Seal chain** — each run's seal chains to the previous run's hash. Tampering any artifact breaks the chain.

**Parquet** — 27-column schema, queryable with DuckDB:

```sql
SELECT package_name, decision, advisory_ids
FROM 'evidence/decisions.parquet'
WHERE vuln_critical > 0 AND team = 'platform';
```

---

## Fail-Open Philosophy

Nothing blocks the build unless OPA says so. Every external call has a timeout. Every failure returns a typed result, never an exception.

| Failure | What happens |
|---------|-------------|
| Scanner binary missing | `ScanResult.not_installed()` — pipeline continues |
| Scanner timeout | `ScanResult.timeout()` — pipeline continues |
| OPA failure | `needs_review` — flagged for human review |
| Database down | `NullRepository` — decisions made, not persisted |
| PyPI unreachable | No age check — pipeline continues |
| Parquet write fails | Logged — decision already stored as JSON |
| LLM fails | Empty string — no advisory, pipeline continues |

---

## Configuration

### CLI (`ADMISSION_*` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMISSION_OPERATING_MODE` | `monitor` | `monitor` or `advise` |
| `ADMISSION_DB_DSN` | — | PostgreSQL DSN (optional — NullRepository fallback) |
| `ADMISSION_EVIDENCE_PATH` | `./evidence` | Evidence + Parquet root |
| `ADMISSION_ENABLED_SCANNERS` | `syft,osv-scanner,trivy,scancode` | Active scanners |
| `ADMISSION_SCANNER_TIMEOUT` | `60` | Per-scanner timeout (s) |
| `ADMISSION_COMBINED_SCANNER_TIMEOUT` | `180` | Combined scanner timeout (s) |
| `ADMISSION_OPA_TIMEOUT` | `10` | OPA timeout (s) |
| `ADMISSION_PIPELINE_TIMEOUT` | `300` | Per-package timeout (s) |
| `ADMISSION_LLM_ENABLED` | `false` | Enable optional LLM task-fit advisory |

### GATEKEEPER (`GATEKEEPER_*` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEKEEPER_GITHUB_TOKEN` | **(required)** | GitHub token for PR comments |
| `GATEKEEPER_ENFORCEMENT_MODE` | `warn` | `block` / `warn` / `log` |
| `GATEKEEPER_LLM_MODEL` | `gpt-4.1` | Copilot agent model |
| `GATEKEEPER_ENABLED_SCANNERS` | `syft,osv-scanner,trivy,scancode` | Pipeline scanners |
| `GATEKEEPER_SEMGREP_TIMEOUT` | `120` | Semgrep timeout (s) |
| `GATEKEEPER_PIPELINE_TIMEOUT` | `300` | Pipeline timeout (s) |
| `GATEKEEPER_POLICY_VERSION` | `1.0.0` | Shown in PR comments |

---

## Repo-Level Configuration

Drop `.eagle-eyed-dom.yaml` at the root of any repo to enable/disable plugins and override thresholds:

```yaml
# .eagle-eyed-dom.yaml
plugins:
  disable:
    - clamav         # disable heavy AV scan in local dev
    - cspell         # disable spell checking for this repo
  enable:
    - gitleaks       # always on, even if disabled globally

thresholds:
  package_age_days: 14          # stricter than default 30
  transitive_count: 100         # stricter than default 200
  complexity_threshold: 15      # cyclomatic complexity limit

licenses:
  forbidden:
    - GPL-3.0-only
    - AGPL-3.0-only
    - SSPL-1.0
    - Commons-Clause
```

### Plugin CLI flags

Override config at the command line for one-off runs:

```bash
# Disable specific plugins for this run
uv run eedom review --repo-path . --all --disable clamav,cspell

# Enable a plugin that is disabled in config
uv run eedom review --repo-path . --all --enable gitleaks

# Combine flags
uv run eedom evaluate --repo-path . --diff changes.diff \
  --disable clamav --enable gitleaks \
  --pr-url "https://github.com/org/repo/pull/1" \
  --team myteam --operating-mode advise
```

---

## SARIF Output

Export findings to SARIF for the GitHub Security tab:

```bash
uv run eedom review --repo-path . --all --format sarif --output results.sarif
```

Upload in GitHub Actions:

```yaml
- name: Run Eagle Eyed Dom
  run: uv run eedom review --repo-path . --all --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF output follows the [SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/). Each plugin maps to a SARIF `tool.driver` — findings are `result` objects with `locations`, `level`, and `ruleId`.

---

## Watch Mode

Re-run plugins automatically on file save during local development:

```bash
# Watch all plugins
uv run eedom review --repo-path . --all --watch

# Watch code analysis only (faster feedback loop)
uv run eedom review --repo-path . --category code --watch
```

Watch mode debounces file-system events (500 ms default). Press `Ctrl+C` to stop.

---

## Monorepo Support

Eagle Eyed Dom auto-discovers packages across a monorepo and runs all 15 plugins per-package.

### Package discovery

Walks the repo recursively and finds all manifest files — `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `requirements.txt`, `Gemfile`, `pom.xml`, `build.gradle`. Each manifest is paired with its lockfile when present. Directories matching `.eedomignore` patterns and standard ignore dirs (`node_modules`, `.git`, `vendor`, `__pycache__`) are skipped.

```bash
# Scan all packages (auto-discovered)
uv run eedom review --repo-path . --all

# Scan a single package
uv run eedom review --repo-path . --package apps/web --all
```

### Per-package output

Findings are grouped by package in the PR comment. Each package gets its own section header and severity score. The overall verdict is the worst across all packages:

```
## apps/web (npm)
...findings...

## libs/core (python)
...findings...
```

### Per-package config overrides

Drop `.eagle-eyed-dom.yaml` inside any package directory to override the root config for that package. Child overrides parent — `apps/web/.eagle-eyed-dom.yaml` overrides `/.eagle-eyed-dom.yaml` for all files under `apps/web/`.

---

## Code Query

Query the CodeGraph SQLite database in plain English. Backed by 12 built-in query templates — no LLM required.

```bash
# Ask a natural language question
eedom query "which functions have the highest fan-out?"

# List all available query templates
eedom query --list
```

Fuzzy matching maps your question to the closest template by keyword overlap. Unrecognized questions fall back to `eedom query --list` with the full template menu.

### Built-in query templates

| Template | What it answers |
|----------|----------------|
| `highest fan-out` | Top functions by outgoing call count |
| `most imported modules` | Fan-in — which modules are depended on most |
| `unused functions` | Orphan symbols with no incoming references |
| `deepest inheritance chains` | Recursive CTE on `inherits` edges |
| `layer violations` | Cross-tier imports (presentation → data direct) |
| `what depends on X` | Upstream walk from a named symbol |
| `what does X call` | Downstream call graph from a named symbol |
| `largest files by symbol count` | Files grouped by defined symbol count |
| `stub functions` | Functions with empty or pass-only bodies |
| `circular imports` | Mutual edge detection |
| `critical path` | Highest-centrality nodes in the call graph |
| `entry points` | Functions with no callers |

---


## Development

```bash
uv sync --group dev                      # Install everything
docker-compose up -d                     # PostgreSQL on port 12432
uv run pytest tests/ -v                  # 1078 tests
uv run ruff check src/ tests/            # Lint
uv run black src/ tests/                 # Format
opa test policies/                       # 16 OPA policy tests
bash scripts/verify-scanners.sh          # Check scanner binaries

# Stress test against real PRs
uv run python scripts/gauntlet.py
```

**Scanner versions** (pinned in Dockerfile): Syft 1.21.0, OSV-Scanner 2.0.1, Trivy 0.70.0, ScanCode 32.3.0, OPA 1.4.2, Semgrep 1.67.0.

---

<div align="center">
  <img src="assets/avatar.png" alt="Eagle Eyed Dom" width="96">
  <br>
  <sub>Eagle Eyed Dom &middot; Dependency Review Agent &middot; v0.1.0</sub>
</div>
