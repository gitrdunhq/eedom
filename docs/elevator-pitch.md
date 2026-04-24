# Eagle Eyed Dom — Technical Brief

## One-liner

Eagle Eyed Dom is a fully deterministic code and dependency review engine for CI — 15 plugins, zero LLM in the decision path, every finding reproducible.

---

## What it does

- Scans every PR that touches a dependency manifest or source file: runs 15 plugins in parallel covering vulnerabilities, license violations, secrets, code smells, unpinned deps, malware, copy-paste, complexity, naming conventions, and K8s misconfiguration
- Evaluates all findings against OPA (Rego) policy rules — producing one of four verdicts: `reject`, `approve_with_constraints`, `approve`, or `needs_review`
- Posts a Markdown PR comment with the verdict (BLOCKED / WARNINGS / ALL CLEAR), a 0–100 severity health score, and per-plugin finding tables; exports the same data as SARIF v2.1.0 for the GitHub Security tab
- Writes a tamper-evident evidence bundle per run — `decision.json` + `memo.md` keyed by commit SHA and timestamp, sealed with a SHA-256 chain — and appends the decision to an append-only Parquet audit log queryable with DuckDB

---

## Technology stack

| Layer | What | Why |
|-------|------|-----|
| Scanners | Syft, OSV-Scanner, Trivy, ScanCode, Semgrep, PMD CPD, kube-linter, Lizard/Radon, cspell, ls-lint, ClamAV, Gitleaks, Supply Chain, Blast Radius | Best-in-class open source tools, each maintained by a dedicated community; swappable via plugin contract |
| Policy | OPA (Rego v1) | Declarative, auditable, version-controlled policy; 6 rules, all individually toggleable |
| Code graph | AST → SQLite | Blast radius, layer violations, dead code, complexity — built locally, no external service, incremental rebuild on file change |
| Output | Markdown + SARIF v2.1.0 | Native GitHub Security tab integration via `upload-sarif` |
| Container | DHI hardened Python 3.13, multi-stage build | All scanner binaries SHA-256 verified at build time; ClamAV signatures fetched at runtime (never baked stale); no secrets in image |
| Evidence | Parquet + SHA-256 seal chain | Append-only audit log, tamper detection, DuckDB-queryable 27-column schema |
| Config | `.eagle-eyed-dom.yaml` + OPA rules | Per-repo plugin enable/disable, threshold overrides, policy-as-code — no forking required |

---

## Security principles

These are not aspirational. They are enforced by the implementation.

**Deterministic-first.** Every finding is reproducible. No model inference, no probabilistic scoring, no "AI confidence." The same input produces the same output every time. OPA decides, not a model.

**Fail-open, fail-loud.** A scanner timeout, a missing binary, a network failure, a database outage — none of these block the build. Every failure is visible in the PR comment with a structured error code. Silent passes are the enemy: `needs_review` is returned, never a phantom clean.

**Zero trust in the decision path.** The optional LLM task-fit advisory is strictly separated: it reads findings after the deterministic engine decides. It never influences the verdict. It is disabled by default (`ADMISSION_LLM_ENABLED=false`) and can be removed with a single config flag.

**Evidence is immutable.** Every scan writes `decision.json` + `memo.md` atomically (temp file → fsync → rename). Each run's seal chains to the previous run's SHA-256 hash. Tampering any artifact breaks the chain. The Parquet audit log is append-only; decisions are never updated in place.

**Supply chain integrity.** Every scanner binary in the container image is SHA-256 verified at build time — the build fails hard on any hash mismatch, no silent pass. ClamAV virus definitions are fetched at container startup, never baked into the image, so they are never stale.

**Policy-as-code.** OPA rules are version-controlled Rego files checked into the repo. Thresholds are configuration, not hardcoded constants. Teams can override thresholds and toggle rules per repo via `.eagle-eyed-dom.yaml` without forking or patching the scanner.

**No shell injection.** All scanner subprocesses are invoked with list-form arguments — `shell=False` throughout. No user-supplied input (diff path, repo path) is concatenated into a shell string.

---

## How it fits

Drop the GitHub Action workflow file (`.github/workflows/gatekeeper.yml`) into any repo; it triggers on PRs that touch dependency manifests or source files and runs the full pipeline in a self-hosted container. The composite `action.yml` is a one-liner:

```yaml
- uses: org/eagle-eyed-dom@main
  with:
    operating-mode: advise
    team: platform
```

GATEKEEPER is a second entry point: a GitHub Copilot Extension that wraps the same deterministic pipeline as an interactive agent for reactive PR review, surfacing structured findings through the Copilot chat interface.

---

## What it doesn't do

**Does not auto-fix.** Eagle Eyed Dom finds and reports. Agentic remediation — where an LLM reads findings, follows per-finding-type rules from config, opens a fix PR, and re-runs the scan to verify — is the v2.0 roadmap item. It is not in the current release.

**Does not replace your SAST or DAST.** It covers dependency vulnerabilities, license risk, secret leakage, code quality, supply chain integrity, and infrastructure misconfiguration. It does not perform dynamic testing, fuzzing, authentication testing, or runtime analysis.

**Does not phone home.** There is no telemetry in the current release. An opt-in telemetry system — collecting only operational signals (plugin success rates, scan times, error codes) with no repo content, no file paths, no package names — is a v1.2 roadmap item. When it ships, it will be opt-in via `.eagle-eyed-dom.yaml` and disabled by default.

---

## License

PolyForm Shield 1.0.0 — free for internal use at any scale, prohibits building a competing product on top of it. No per-seat fees, no usage limits, no call-home requirement.

The enterprise orchestrator (fleet management, org-wide compliance controller, deploy gate) is a separate repo under BSL 1.1 with a 3-year conversion to Apache-2.0.
