# `dep-audit` Plugin — Phase B: File Layout, Delivery, Catalog, Reuse

## File Layout

**New private repo `gitrdunhq/eedom-dep-audit/`:**

```
eedom-dep-audit/
├── pyproject.toml                                 # entry-point + deps on eedom>=X
├── README.md
├── LICENSE-COMMERCIAL.txt
├── migrations/
│   └── 003_dep_audit.sql                          # DDL from Phase A
├── src/eedom_dep_audit/
│   ├── __init__.py
│   ├── plugin.py                                  # DepAuditPlugin(ScannerPlugin)
│   ├── run_context.py                             # RunContext, snapshot pinning
│   ├── snapshot.py                                # snapshot_id computation
│   ├── catalog/
│   │   ├── __init__.py
│   │   ├── protocol.py                            # CatalogBackend Protocol
│   │   ├── local_postgres.py                      # LocalPostgresCatalog
│   │   └── firka_api.py                           # FirkaApiCatalog
│   ├── graph/
│   │   ├── builder.py                             # builds dep_graph_edge from CycloneDX
│   │   ├── propagator.py                          # walks edges, classifies min_edge_type
│   │   └── edge_classifier.py                     # runtime/build/dev/test/optional/peer
│   ├── reachability/
│   │   ├── python_reach.py                        # wraps blast_radius for Python
│   │   └── js_reach.py                            # NEW: TS/JS AST → CodeGraph (phase 2)
│   ├── contextual_cvss.py                         # rule-based re-scoring (phase 3)
│   ├── exploit_signals/
│   │   ├── kev.py                                 # CISA KEV ingest (phase 4)
│   │   └── exploitdb.py                           # ExploitDB scrape (phase 4)
│   ├── refresh.py                                 # `eedom dep-audit refresh` verb
│   ├── render.py                                  # template_context override
│   └── templates/dep-audit.md.j2
└── tests/
    ├── unit/
    │   ├── test_dep_audit_plugin.py
    │   ├── test_snapshot.py
    │   ├── test_propagator.py
    │   ├── test_edge_classifier.py
    │   ├── test_local_postgres_catalog.py
    │   └── test_properties.py                     # Hypothesis class
    └── conftest.py
```

**Upstream eedom patch (one file):**
- `src/eedom/core/registry.py` — entry-point discovery (~15 lines, additive). See Phase A Decision 3.

## Phased Delivery

| Phase | Shippable outcome | New code | Migrations |
|---|---|---|---|
| **1. Chain propagation + edge classification** | "We can show every CVE, the full transitive path to it, and tag the path runtime/build/dev/test/optional." | `plugin.py`, `run_context.py`, `snapshot.py`, `graph/`, `catalog/protocol.py`, `catalog/local_postgres.py`, `refresh.py`, registry patch | `003_dep_audit.sql` |
| **2. Symbol-level reachability** | "We can mark each CVE `reachable=true/false` from app entry points using AST call graphs." | `reachability/python_reach.py` (wraps `CodeGraph.blast_radius`), `reachability/js_reach.py` (extends `graph_builder._index_javascript` for cross-file resolution) | `004_reachable_evidence.sql` adds `reachable_evidence_path TEXT` to `cve_propagation` |
| **3. CVSS contextualization** | "Each CVE gets a `contextual_cvss` adjusting base score by `min_edge_type` and `reachable`." | `contextual_cvss.py`; OPA rule additions in `policies/` (consumed but not owned by plugin) | populates `contextual_cvss` |
| **4. Exploit-availability** | "Findings are tagged `kev_listed` / `epss_score` / `exploit_pub`." | `exploit_signals/kev.py`, `exploit_signals/exploitdb.py`, `catalog/firka_api.py` | `005_epss.sql`; `kev_signals` populated |

## Pluggable Catalog Backend

```python
# src/eedom_dep_audit/catalog/protocol.py
from typing import Protocol, Iterable

class CatalogBackend(Protocol):
    def begin_snapshot(self, snapshot_id: str) -> None: ...
    def get_package(self, ecosystem: str, name: str, version: str) -> dict | None: ...
    def list_edges(self, snapshot_id: str, parent: tuple[str, str, str]) -> Iterable[dict]: ...
    def upsert_edges(self, snapshot_id: str, edges: list[dict]) -> None: ...
    def get_advisories(self, snapshot_id: str, ecosystem: str, name: str,
                       version: str) -> list[dict]: ...
    def upsert_propagation(self, snapshot_id: str, repo_name: str,
                           rows: list[dict]) -> None: ...
    def lookup_kev(self, cve_id: str) -> dict | None: ...
    def get_snapshot(self, snapshot_id: str) -> dict | None: ...
    def commit_snapshot(self, snapshot_id: str) -> None: ...
```

Two implementations:

- **`LocalPostgresCatalog(pool, conn=None)`** — wraps `psycopg_pool.ConnectionPool`. When constructed with a pre-acquired `conn`, all calls reuse that connection (the REPEATABLE READ trick from Phase A Decision 1). Fail-open like `PackageCatalog` in `src/eedom/data/catalog.py:84`.
- **`FirkaApiCatalog(base_url, api_key, http=httpx.Client)`** — REST client. `begin_snapshot` POSTs to `/v1/snapshots`, server returns the same `snapshot_id` if content matches. Same timeout/retry shape as `PyPIClient` (`src/eedom/data/pypi.py:27`). New settings on `EedomSettings`: `firka_api_url`, `firka_api_key`, `dep_audit_backend ∈ {local_postgres, firka_api}`.

## Reuse Table

| Building block | Path | Recommendation |
|---|---|---|
| `ScannerPlugin` ABC | `src/eedom/core/plugin.py:34` | **Subclass directly.** `name="dep-audit"`, `category=PluginCategory.dependency`, `depends_on=["syft"]` (needs CycloneDX SBOM produced by Syft plugin). |
| `PluginRegistry` discovery | `src/eedom/core/registry.py:233` | **Patch** — add entry-point loop (Phase A Decision 3). Only upstream change. |
| `Finding` model + dedup | `src/eedom/core/models.py:124` and `core/normalizer.py:23` | **Reuse unchanged.** Each `(advisory_id, leaf_pkg, path_hash)` becomes one Finding; severity wins via existing dedup. |
| `build_opa_input` | `src/eedom/core/policy.py:48` | **Reuse**, but extend Finding with `dep_audit_path` + `min_edge_type` fields so OPA can write `data.dep_audit.deny` rules. Remember `input.pkg`, NOT `input.package`. |
| `PackageCatalog` | `src/eedom/data/catalog.py:78` | **Wrap, don't extend.** `LocalPostgresCatalog` composes `PackageCatalog` for node lookups; new tables accessed directly via the pinned connection. |
| `package_catalog` table | `migrations/002_package_catalog.sql:16` | **Extend by reuse**, no schema changes. Plugin backfills `transitive_dep_count` per snapshot. |
| `PyPIClient` | `src/eedom/data/pypi.py:19` | **Use only inside `refresh.py`**, never inside the audit hot path. Implement `count_transitive_deps` (currently a stub returning None) as a side-effect of `refresh`. |
| `OsvScanner` | `src/eedom/data/scanners/osv.py:38` | **Reuse inside `refresh.py`** to populate `cve_node_join`. Plugin run does not invoke it. |
| `discover_packages` | `src/eedom/core/manifest_discovery.py:94` | **Reuse unchanged.** Per-package execution mode in `registry._run_all_per_package` already passes `package_root`. |
| `_build_dep_summary` | `src/eedom/agent/tools.py:129` | **Steal the purl-resolution logic into `graph/builder.py`** (depth-1 cap is wrong for us). Don't import — copy the parser, walk full depth. |
| `CodeGraph` | `src/eedom/plugins/_runners/graph_builder.py:80` | **Reuse for phase 2.** `python_reach.py` calls `CodeGraph(db_path=":memory:")`, then `index_directory()`, then `blast_radius(symbol, max_depth)` per CVE-affected symbol. JS path needs new resolver. Signature confirmed: `blast_radius(symbol_name: str, max_depth: int = 3) -> list[dict]` at `graph_builder.py:163`. |
| `EvidenceStore` | `src/eedom/data/evidence.py:21` | **Reuse unchanged.** Audit writes JSONL evidence per snapshot at `evidence/{commit_sha}/{snapshot_id}/dep-audit.jsonl`. |
| `EedomSettings` | `src/eedom/core/config.py:41` | **Extend** with `dep_audit_backend`, `firka_api_url`, `firka_api_key`, `dep_audit_max_depth` (default 25). Respect existing `scanner_timeout=60s` for refresh; audit reads from DB so should be sub-second. |
