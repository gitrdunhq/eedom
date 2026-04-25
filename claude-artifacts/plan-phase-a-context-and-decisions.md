# `dep-audit` Plugin — Phase A: Context & Validated Decisions

## Context

eedom already runs `syft` (SBOM), `osv-scanner` and `trivy` (vuln lookups), `scancode` (licenses), `supply-chain` (unpinned deps). Each reports findings on **direct** packages but none of them:

1. Resolve the **full transitive dependency graph** with edge metadata (runtime / build / dev / test / optional / peer).
2. Propagate a CVE **upward** through the graph and answer *"does this CVE actually reach my code, via what path, and at which layer?"*
3. Cache the resolved graph + CVE-to-package mappings **centrally** so the same `(pkg, version)` is never re-resolved across repos / CI runs.

The user wants a private, paid-tier plugin that does this — sold as the middle tier for **Firka** (proprietary agentic dev orchestrator that manages fleets of AI coding agents and enforces quality gates). Determinism target is 100%.

## User scoping decisions

- **v1 ecosystems:** Python (PyPI) + JavaScript (npm/yarn/pnpm). Java/Go/Rust are v2.
- **CVE depth, phased biggest-payoff first:**
  1. Chain propagation + edge classification (runtime/build/dev/test/optional)
  2. Symbol-level reachability (uses an AST call graph — `blast-radius` already does Python; we'd need JS)
  3. CVSS contextualization (rule-based re-scoring)
  4. Exploit-availability (CISA KEV + ExploitDB signals)
- **Location:** Separate private repo `gitrdunhq/eedom-dep-audit`, distributed as a wheel, registered via Python entry-point so eedom's `PluginRegistry` auto-discovers on install.
- **Central catalog:** Hybrid — local Postgres (port 12432, existing `package_catalog`) for self-hosted; Firka API for SaaS.

## Decision 1 — Determinism (validated, expanded)

`resolver_snapshot_id = sha256(...)` is correct in spirit but has three holes that must be closed:

1. **`psycopg_pool` does not give snapshot isolation across connections.** Pool is `min=1/max=10` (`src/eedom/data/db.py:94`). A run that touches catalog + OSV + KEV + EPSS in sequence can pick up different versions of `package_catalog` mid-scan because each `with self._pool.connection()` returns a different backend pid; default isolation is `READ COMMITTED`.
   - **Fix:** Borrow **one** connection for the whole audit run, execute `BEGIN ISOLATION LEVEL REPEATABLE READ`, pass that connection through. This is a real Postgres snapshot.
2. **OSV / npm / PyPI have no snapshot id.** The only way to get determinism is to **mirror** them into our own catalog and read exclusively from there during a run. The plugin must NOT call `osv-scanner` / PyPI live during audit — only inside a separate `eedom dep-audit refresh` verb that bumps a `vuln_index_version` row.
3. **`updated_at` in the hash is wrong granularity.** Hash the **content** (canonical JSON of semantic columns) not the row's mtime — two replays into a clean DB would otherwise differ.

**Concrete plan:**
- `RunContext` holds **one** psycopg connection in `REPEATABLE READ` for the entire run.
- New table `audit_snapshot(snapshot_id PK, vuln_index_version, kev_version, epss_version, content_hash, created_at)`.
- `snapshot_id = sha256(canonical(content_hash || vuln_index_version || kev_version || epss_version || repo_lockfile_hash))`. Wallclock not included.
- Refresh is a separate CLI verb. Audits never write to upstream-mirror tables.
- Property test asserts byte-identical findings across two runs against the same `snapshot_id`.

## Decision 2 — Schema additions (validated)

**Reuse `package_catalog` for nodes; do NOT create `dep_graph_node`.** It already has `(ecosystem, package_name, version)` UNIQUE plus `transitive_dep_count` (currently NULL), `vuln_scanned_at`, `sbom_path` (`migrations/002_package_catalog.sql:16`).

`cve_propagation` is a **real table**, not a materialized view: (a) we need to write `path_jsonb` from the plugin, (b) deterministic replay requires writing rows tied to `snapshot_id`, (c) MV refresh under REPEATABLE READ is awkward.

Migration 003 (`gitrdunhq/eedom-dep-audit/migrations/003_dep_audit.sql`):

```sql
BEGIN;

CREATE TABLE IF NOT EXISTS audit_snapshot (
  snapshot_id        TEXT PRIMARY KEY,
  vuln_index_version TEXT NOT NULL,
  kev_version        TEXT,
  epss_version       TEXT,
  content_hash       TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE dep_edge_type AS ENUM
  ('runtime','build','dev','test','optional','peer');

CREATE TABLE IF NOT EXISTS dep_graph_edge (
  parent_ecosystem TEXT NOT NULL,
  parent_name      TEXT NOT NULL,
  parent_version   TEXT NOT NULL,
  child_ecosystem  TEXT NOT NULL,
  child_name       TEXT NOT NULL,
  child_version    TEXT NOT NULL,
  edge_type        dep_edge_type NOT NULL,
  snapshot_id      TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  PRIMARY KEY (snapshot_id, parent_ecosystem, parent_name, parent_version,
               child_ecosystem, child_name, child_version, edge_type)
);
CREATE INDEX idx_edge_child ON dep_graph_edge
  (snapshot_id, child_ecosystem, child_name, child_version);

CREATE TABLE IF NOT EXISTS cve_node_join (
  advisory_id   TEXT NOT NULL,
  ecosystem     TEXT NOT NULL,
  package_name  TEXT NOT NULL,
  version_range TEXT NOT NULL,    -- canonicalized via packaging.specifiers.SpecifierSet
  vector        JSONB,
  kev_listed    BOOLEAN NOT NULL DEFAULT false,
  epss_score    NUMERIC(5,4),
  snapshot_id   TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  PRIMARY KEY (snapshot_id, advisory_id, ecosystem, package_name, version_range)
);

CREATE TABLE IF NOT EXISTS cve_propagation (
  snapshot_id     TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  repo_name       TEXT NOT NULL,
  advisory_id     TEXT NOT NULL,
  root_ecosystem  TEXT NOT NULL,
  root_name       TEXT NOT NULL,
  root_version    TEXT NOT NULL,
  leaf_ecosystem  TEXT NOT NULL,
  leaf_name       TEXT NOT NULL,
  leaf_version    TEXT NOT NULL,
  path_jsonb      JSONB NOT NULL,
  min_edge_type   dep_edge_type NOT NULL,
  reachable       BOOLEAN,              -- NULL until phase 2 sets it
  contextual_cvss NUMERIC(3,1),         -- NULL until phase 3
  PRIMARY KEY (snapshot_id, repo_name, advisory_id, root_name, root_version,
               leaf_name, leaf_version)
);
CREATE INDEX idx_cve_prop_repo ON cve_propagation (repo_name, advisory_id);

CREATE TABLE IF NOT EXISTS kev_signals (
  cve_id    TEXT PRIMARY KEY,
  listed_at TIMESTAMPTZ NOT NULL,
  due_date  TIMESTAMPTZ,
  vendor    TEXT,
  product   TEXT
);

COMMIT;
```

Note: `peer` edge type is JS-only (PyPI has no peer concept). `transitive_dep_count` in `package_catalog` becomes a derived value the plugin backfills per snapshot.

## Decision 3 — Entry-point loading (validated)

Group: **`eedom.plugins`** (singular pluralized package, matches `src/eedom/plugins/` layout). Not `scanner_plugins` — that implies a sub-category that doesn't match the existing `PluginCategory` enum.

Upstream patch (`src/eedom/core/registry.py`, additive ~15 lines after the existing dir-scan loop at line 233):

```python
def discover_plugins(plugin_dir: Path) -> list[ScannerPlugin]:
    plugins: list[ScannerPlugin] = []
    # ... existing dir-scan loop unchanged ...

    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group="eedom.plugins"):
            try:
                cls = ep.load()
                if (isinstance(cls, type) and issubclass(cls, ScannerPlugin)
                        and cls is not ScannerPlugin):
                    plugins.append(cls())
            except Exception as exc:
                logger.warning("plugin.entry_point_failed",
                               name=ep.name, error=str(exc))
    except Exception:
        logger.debug("plugin.entry_points_unavailable")

    return plugins
```

Plugin's `pyproject.toml`:
```toml
[project.entry-points."eedom.plugins"]
dep-audit = "eedom_dep_audit.plugin:DepAuditPlugin"
```

This is the **only** change to the eedom repo. Everything else lives in the private plugin repo.
