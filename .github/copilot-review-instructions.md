# Copilot Review Instructions

## What eedom already covers — skip these

Eagle Eyed Dom runs 15 deterministic plugins on every PR. Do not duplicate these checks — they are already enforced by the `GATEKEEPER Review` CI job and surfaced via the `dom:` label system.

| Category | Covered by | What it catches |
|----------|-----------|-----------------|
| Vulnerabilities | OSV-Scanner, Trivy | Known CVEs across 18 ecosystems |
| Licenses | ScanCode | GPL, AGPL, SSPL, forbidden license detection |
| Secrets | Gitleaks | API keys, tokens, passwords (800+ patterns) |
| Supply chain | Supply Chain plugin | Unpinned deps, missing lockfiles, package age < 30d, malware |
| Complexity metrics | Lizard + Radon | Cyclomatic complexity, maintainability index |
| Copy-paste | PMD CPD | Token-based duplication across 12 languages |
| Spelling | cspell | Code-aware spell checking |
| File naming | ls-lint | Naming convention enforcement |
| K8s security | kube-linter | Resource limits, privileged containers, latest tags |
| Code patterns | Semgrep | AST pattern matching with org rulesets |
| Blast radius | Code graph | High fan-out, layer violations, dead code, stub detection |
| Policy | OPA | 6 Rego rules: deny/warn/approve verdict |
| SBOM | Syft | CycloneDX bill of materials |
| Malware | ClamAV | Virus/malware scanning |

**If you're about to comment on a CVE, a leaked secret, a license issue, unpinned deps, or cyclomatic complexity — stop. Dom already caught it or it's not there.**

---

## What to review — things that require judgment

Focus your review on what deterministic tools cannot catch. Every comment should be something a scanner can't flag.

### 1. Business logic correctness

Does the code do what the PR description says it does? Are the calculations right? Does the state machine transition correctly? Are the edge cases handled?

Look for:
- Off-by-one errors in loops and slices
- Incorrect boolean logic (De Morgan violations, inverted conditions)
- Missing branches in match/switch statements
- Null/None handling that produces silent wrong answers instead of errors
- Time zone assumptions in date/time logic

### 2. API and interface design

Is this the right interface for callers? Will it be painful to use or extend?

Look for:
- Functions that take too many parameters (>5 is a smell)
- Boolean parameters that control branching ("stringly typed" APIs)
- Leaking internal types across module boundaries
- Breaking changes to existing public interfaces without migration
- Return types that force callers to do extra work (returning raw dicts when a typed object would be clearer)

### 3. Concurrency and race conditions

Deterministic scanners can't reason about runtime interleaving.

Look for:
- Shared mutable state without synchronization
- Check-then-act patterns (TOCTOU)
- Async code that blocks the event loop
- Database operations that assume serializable isolation without enforcing it
- Cache invalidation timing windows

### 4. Error handling strategy

Not "is there a try/catch" — eedom's semgrep rules catch missing timeouts and bare exception swallowing. Instead: is the error handling *correct for this context*?

Look for:
- Catching too broadly and masking the real error
- Error recovery that leaves state inconsistent
- Missing rollback/cleanup on partial failure
- Error messages that leak internal details to external callers
- Retry logic that can amplify failures (retry storms)

### 5. Performance implications

Algorithmic and architectural performance — not microbenchmarks.

Look for:
- N+1 query patterns (loop with a query inside)
- Unbounded collection growth (lists/dicts that grow with input size without limits)
- Quadratic or worse algorithms where linear exists
- Missing pagination on list/search endpoints
- Blocking I/O in hot paths
- Large allocations in frequently called code

### 6. Test quality

Eedom checks that `# tested-by:` annotations exist and flags stub functions. But it can't tell whether the tests are *good*.

Look for:
- Tests that pass when the implementation is deleted (weak assertions)
- Tests that only cover the happy path
- Mocking the thing being tested instead of its dependencies
- Tests coupled to implementation details rather than behavior
- Missing edge case coverage (empty inputs, max values, unicode, concurrent access)

### 7. Security logic

Eedom catches secrets in code, known CVEs, and AST-level injection patterns. It cannot reason about authorization flows, authentication logic, or trust boundaries.

Look for:
- Missing authorization checks on new endpoints
- Privilege escalation paths (user A can access user B's data)
- Trust boundary violations (treating external input as trusted after a single check)
- Session handling issues (fixation, insufficient expiry)
- Audit logging gaps on sensitive operations

### 8. Data model and migration safety

Look for:
- Schema changes that break backwards compatibility
- Migrations that lock large tables
- NOT NULL columns added without defaults on existing data
- Index changes that affect query plans
- Data type changes that lose precision (float→int, timestamp→date)

### 9. Naming and readability

Not syntactic naming (ls-lint covers conventions) — semantic clarity.

Look for:
- Names that mislead about what the code does
- Abbreviations that aren't obvious to the team
- Boolean variables/functions without clear true/false semantics
- Functions named "process" or "handle" that do too many things
- Comments that describe *what* instead of *why* (the code already says what)

### 10. Backwards compatibility

Look for:
- Changed function signatures without updating all callers
- Removed or renamed public exports
- Changed serialization formats (JSON field names, protobuf field numbers)
- Environment variable renames without migration support
- Config file format changes without version detection

---

## How to comment

- **Be specific.** "This might have a race condition" is noise. "Lines 42-47: the read and write to `_cache` aren't synchronized — concurrent requests can see stale data after the TTL check on L43 passes but before the write on L47 completes" is useful.
- **Explain the impact.** Not just what's wrong, but what happens if it ships.
- **Suggest a fix.** Or at least a direction. "Consider using a lock here" beats "this is unsafe."
- **Skip nits.** If eedom or the formatter would catch it, don't comment on it. Your time is better spent on the 10 categories above.
