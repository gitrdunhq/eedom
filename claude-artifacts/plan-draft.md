# Deep Transitive Dependency Audit Plugin (working title: `dep-audit`)

> **Status:** Investigation / draft. Scoping questions outstanding — see "Open Questions" at bottom.

## Context

eedom already runs `syft` (SBOM), `osv-scanner` and `trivy` (vuln lookups), `scancode` (licenses) and `supply-chain` (unpinned deps). These plugins each report findings on **direct** packages but none of them:

1. Resolve the **full transitive dependency graph** with edge metadata (runtime / build / dev / test / optional).
2. Propagate a CVE **upward** through the graph and answer the question *"does this CVE actually reach my code, and if so via what path and at which layer (runtime vs build)?"*
3. Cache the resolved graph + CVE-to-package mappings **centrally** so the same `(pkg, version)` is never re-resolved across repos / CI runs.

The user wants a private, paid-tier plugin that does this — to be sold as the middle tier for **Firka** (sibling product in `gitrdunhq/firka`). Determinism target is 100%.

## Building blocks already in the repo (reuse, don't re-implement)

| Need | Existing component | Path |
|---|---|---|
| Plugin contract | `ScannerPlugin` ABC, `PluginResult`, `depends_on` | `src/eedom/core/plugin.py:34` |
| Auto-discovery / topo sort | `PluginRegistry`, `_topological_sort` | `src/eedom/core/registry.py:28,62` |
| Finding shape & dedup | `Finding`, `FindingSeverity`, `FindingCategory`, `normalize_findings` | `src/eedom/core/models.py:57,93,124`, `src/eedom/core/normalizer.py:23` |
| OPA input builder | `build_opa_input` (`input.pkg`, not `input.package`) | `src/eedom/core/policy.py:48` |
| Central cache (Postgres, TTLs) | `CatalogEntry`, `DecisionRepository` | `src/eedom/data/catalog.py:23`, `src/eedom/data/db.py:70` |
| Evidence chain | `EvidenceStore` (atomic write, keyed by request_id+SHA) | `src/eedom/data/evidence.py:21` |
| Timeout / fail-open orchestration | `ScanOrchestrator` | `src/eedom/core/orchestrator.py:29` |
| Settings / env vars | `EedomSettings` | `src/eedom/core/config.py:41` |
| Property-test patterns (DPS-12) | Hypothesis `@given` + `TestProperties` | `tests/unit/test_sbom_diff.py`, `tests/unit/test_parquet_writer.py` |

## Sketch of the new plugin (to be refined after scoping answers)

- **Name:** `dep-audit` (subject to change)
- **Category:** `dependency`
- **`depends_on`:** `["syft"]` — consume Syft's CycloneDX SBOM as the source of truth for direct deps + ecosystem detection, then walk further.
- **Pipeline:**
  1. Parse manifests/lockfiles → seed nodes with **edge type** (runtime / build / dev / test / optional).
  2. Resolve transitive graph via cached resolver. Cache key = `(ecosystem, name, version)` + `resolver_snapshot_id`.
  3. Pull CVE/advisory data (OSV) per node, also cached centrally with TTL.
  4. **Propagate** each CVE upward through reverse edges, classifying impact by edge type union (e.g. "reachable only via dev").
  5. (Optional) Reachability check using `blast-radius` AST graph to mark CVEs as *reachable* vs *latent*.
  6. Emit `Finding`s with new fields: `dep_path`, `edge_classification`, `reachability`, `propagation_distance`.
- **Determinism strategy:** every external lookup is pinned to a **snapshot id** (OSV/PyPI/npm registry checkpoint). No clock-dependent inputs in the hot path. Cache TTL only refreshes the snapshot, never invalidates within a snapshot.

## Open Questions (for the user)

1. Ecosystems in v1?
2. What does "smart CVE analysis" mean — propagation only, reachability, exploit context, all of the above?
3. Where does the plugin live — inside eedom repo (license-gated) or as a separate private package?
4. Firka integration model — what is Firka and how does this plugin plug in as the middle tier?

(Plan will be filled in once these are answered.)
