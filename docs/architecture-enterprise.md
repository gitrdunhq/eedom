# Enterprise Architecture Assessment

Evaluation of eedom for self-hosted, business, and enterprise deployment models.

Based on: `ARCHITECTURE.md`, `src/eedom/core/config.py`, `src/eedom/core/pipeline.py`,
`src/eedom/data/db.py`, `src/eedom/data/catalog.py`, `src/eedom/data/evidence.py`,
`Dockerfile`, `docker-compose.yml`, `.github/workflows/`, and `migrations/`.

---

## 1. Current State Summary

Eedom is a single-tenant CLI tool designed for individual repo scanning. Key observations:

- **Single Postgres database** with a connection pool (`min_size=1, max_size=10`) in `data/db.py:85`. No tenant isolation at any layer.
- **File-based evidence** written to a local `./evidence` directory (`core/config.py:62`). No object storage integration.
- **Flat configuration** via `EEDOM_*` environment variables in `EedomSettings` (`core/config.py:41`). No per-tenant or per-repo config hierarchy.
- **Synchronous pipeline** executed inline by the CLI or GitHub Action (`core/pipeline.py:73`). No queue-based async processing.
- **Single container image** (`Dockerfile`) packages all 15 plugins, all scanner binaries, and the full Python stack into one image. No service decomposition.
- **docker-compose.yml** defines only a single Postgres instance. No Redis, no queue broker, no separate workers.
- **Scan queue table** exists (`migrations/002_package_catalog.sql:85`) but has no worker implementation pulling from it.
- **GATEKEEPER workflow** (`gatekeeper.yml`) runs on `self-hosted` runners and executes scanning synchronously within the workflow job.

---

## 2. Multi-Tenancy

### Current: Zero Isolation

All tables in `migrations/001_initial_schema.sql` and `002_package_catalog.sql` are flat. No `tenant_id` column exists on any table. `DecisionRepository` (`data/db.py:66`) connects to a single DSN with a single pool. `PackageCatalog` (`data/catalog.py:78`) shares the entire `package_catalog` table across all queries.

### Option A: Postgres Row-Level Security (RLS)

Add a `tenant_id UUID NOT NULL` column to every table. Apply RLS policies that filter rows based on `current_setting('app.tenant_id')`.

**Changes required:**

| File | Change |
|------|--------|
| `migrations/003_multi_tenancy.sql` | New migration: add `tenant_id` to all tables, create RLS policies, add composite indexes |
| `data/db.py` | Set `app.tenant_id` via `SET LOCAL` after acquiring connection (alongside existing `SET LOCAL statement_timeout` at line 106) |
| `data/catalog.py` | Same `SET LOCAL` pattern needed in every method |
| `core/config.py` | Add `tenant_id: str` field to `EedomSettings` |
| `core/pipeline.py` | Pass tenant context through to DB layer |

**Pros:** Single database, simpler ops, shared `package_catalog` benefits all tenants.
**Cons:** One bad migration can expose cross-tenant data. RLS performance degrades on large tables without proper indexing. pgvector HNSW index (`idx_catalog_embedding`) is global and cannot be partitioned by tenant.

**Recommendation:** RLS is viable for up to ~50 tenants sharing one Postgres instance. Beyond that, query planning overhead on the `package_catalog` table (which has a global HNSW index) becomes a bottleneck.

### Option B: Separate Database Per Tenant

Each tenant gets its own Postgres database (or schema). `DecisionRepository.__init__` already accepts a `dsn` parameter -- a tenant router resolves `tenant_id` to the correct DSN.

**Changes required:**

| File | Change |
|------|--------|
| New: `data/tenant_router.py` | Maps `tenant_id -> dsn`. Could be backed by a control-plane DB or config file |
| `data/db.py` | Accept DSN from router instead of `EedomSettings.db_dsn` |
| `data/catalog.py` | Loses cross-tenant package sharing (each tenant has its own catalog) |
| `Dockerfile` | No change -- routing is runtime config |

**Pros:** Hard isolation, simpler security audit, each tenant can be on a different Postgres version.
**Cons:** Loses the shared `package_catalog` -- the same package is scanned N times across N tenants. Ops complexity grows linearly with tenant count.

**Recommendation:** Separate DBs for regulated customers (FedRAMP, financial services). RLS for the general multi-tenant case.

---

## 3. Scalability

### What Breaks at 100 Repos

| Bottleneck | Location | Symptom |
|-----------|----------|---------|
| Connection pool exhaustion | `db.py:85` — `max_size=10` | Concurrent pipelines block waiting for connections |
| Parquet append contention | `parquet_writer.py:122-128` — read-entire-file + write | Two concurrent runs on the same evidence root corrupt the file |
| Evidence directory growth | `evidence.py` — one dir per `<sha>/<timestamp>` | 100 repos x 10 PRs/day = 1000 dirs/day, inode exhaustion on ext4 |
| Scanner binary contention | `orchestrator.py:50` — ThreadPoolExecutor per run | 100 concurrent runs x 4 scanners = 400 threads per node |
| Single OPA subprocess | `core/policy.py` — `subprocess.run()` per evaluation | OPA cold-starts are ~200ms each; 100 concurrent evals = serial bottleneck |

### What Breaks at 1000 Repos

All of the above, plus:
- The `package_catalog` table becomes the hot path. `vuln_scanned_at` expiry checks (`catalog.py:48-64`) run per-request without caching.
- `scan_queue` table (`002_package_catalog.sql:85`) has no worker implementation. At 1000 repos, you cannot rely on synchronous scanning per PR.
- `decisions.parquet` becomes a single multi-GB file that must be fully read on every append (`parquet_writer.py:123`).
- HNSW index rebuild on `description_embedding` blocks writes during vacuum.

### Distributed Scanning via scan_queue

The schema is already there:

```sql
-- migrations/002_package_catalog.sql:85
CREATE TABLE IF NOT EXISTS scan_queue (
    queue_id UUID PRIMARY KEY,
    scan_type TEXT CHECK (scan_type IN ('full', 'vuln_only', 'rescan')),
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    ...
);
```

And `PackageCatalog.queue_scan()` (`catalog.py:289`) already inserts into it. What is missing:

| Missing piece | What to build |
|--------------|---------------|
| Worker process | New `src/eedom/worker/scanner_worker.py` that polls `scan_queue WHERE status='pending' ORDER BY priority DESC, created_at ASC` with `SELECT ... FOR UPDATE SKIP LOCKED` |
| Result writer | Worker runs `ScanOrchestrator.run()` then calls `catalog.upsert()` with findings |
| Status callback | Worker updates `scan_queue.status` to `completed`/`failed` and sets `completed_at` |
| Pipeline integration | `ReviewPipeline.evaluate()` checks catalog freshness before running scanners. If fresh, skip scanners and use cached findings |
| Heartbeat | Worker sets `started_at` on pickup; a reaper marks stale `processing` rows as `failed` after 10 minutes |

This converts eedom from "scan per PR" to "scan per unique package version, cache results." At 1000 repos, most PRs hit the cache and complete in <1 second instead of 60-180 seconds.

### Parquet Partitioning

Replace the single `decisions.parquet` with partitioned writes:

```
evidence/
  decisions/
    year=2026/month=04/
      decisions-20260424T1430.parquet   # one file per run
```

**Change in `parquet_writer.py`:** Instead of read-all + append + write-all, write a new Parquet file per run into a partitioned directory. DuckDB queries work identically with `read_parquet('evidence/decisions/**/*.parquet')`.

---

## 4. High Availability

### Current: Single Points of Failure

| Component | SPOF | Impact |
|-----------|------|--------|
| Postgres | Single instance in `docker-compose.yml` | All persistence lost; pipeline falls back to `NullRepository` (fail-open) |
| Evidence directory | Local filesystem | If the node dies, evidence for in-flight runs is lost |
| Self-hosted runner | Single runner in `gatekeeper.yml` | PRs queue up until the runner recovers |
| OPA binary | Local subprocess | Policy evaluations degrade to `needs_review` (fail-open) |

### HA Architecture

**Postgres:** Deploy a streaming replication cluster (Patroni + etcd, or AWS RDS Multi-AZ). `db.py` already uses psycopg3 connection pooling -- point the DSN at a PgBouncer or HAProxy that routes to the current primary. Read replicas can serve `PackageCatalog.lookup()` and `search_semantic()`.

**Evidence storage:** Move from local filesystem to a shared filesystem (NFS/EFS) or object storage (S3/GCS). `EvidenceStore` (`evidence.py:37`) takes a `root_path` string -- pointing this at an NFS mount requires zero code changes. Object storage requires a new `ObjectEvidenceStore` implementation behind `EvidenceStoreProtocol`.

**Runners:** Use a runner pool (3+ self-hosted runners with the same label). The `gatekeeper.yml` workflow already uses `runs-on: self-hosted` -- adding more runners with that label provides automatic HA.

**OPA:** Deploy OPA as a sidecar or daemon (HTTP mode). Replace `subprocess.run()` calls in `core/policy.py` with HTTP POST to `localhost:8181/v1/data/policy`. Eliminates cold-start latency and supports warm standby.

---

## 5. Centralized Policy Management

### Current State

OPA policies live in `policies/policy.rego` and are baked into the container image (`Dockerfile` line 204: `COPY --from=builder /opt/eedom/policies/ /opt/eedom/policies/`). The `opa_policy_path` config (`config.py:72`) defaults to `./policies`.

Per-repo configuration uses `.eagle-eyed-dom.yaml` for plugin enable/disable and thresholds (`core/repo_config.py`). There is no centralized policy hierarchy.

### Enterprise Policy Hierarchy

```
org-level policy (enforced, cannot be overridden)
  |
  v
team-level policy (can relax org defaults for specific teams)
  |
  v
repo-level policy (.eagle-eyed-dom.yaml — can relax team defaults)
```

**Implementation:**

| File | Change |
|------|--------|
| New: `migrations/003_policy_management.sql` | `org_policies` table: `(org_id, policy_rego TEXT, forbidden_licenses JSONB, min_package_age_days INT, ...)` |
| New: `core/policy_hierarchy.py` | Merge logic: org policy sets floor, team/repo can only relax within bounds |
| `core/policy.py` | `OpaEvaluator` fetches merged policy from DB instead of reading from filesystem |
| `core/config.py` | Add `org_id: str | None` and `team_id: str | None` to `EedomSettings` |
| `core/repo_config.py` | `load_repo_config()` merges repo-level YAML with DB-backed team/org policy |

**OPA bundle server:** For large deployments, run an OPA bundle server that distributes policy bundles. Each eedom instance pulls its merged policy bundle at startup and on a polling interval. This eliminates the need to bake policies into the container image.

---

## 6. RBAC for Verdict Overrides

### Current State

The `bypass_records` table (`migrations/001_initial_schema.sql:66`) stores overrides with `invoked_by` and `reason` fields. `DecisionRepository.save_bypass()` (`db.py:370`) writes these records. There is no authorization check -- anyone who can call the CLI can bypass.

### RBAC Model

```
Role: viewer    — read decisions, evidence
Role: operator  — run scans, view results
Role: approver  — override verdicts (reject -> approve)
Role: admin     — manage policies, manage users, all of the above
```

**Implementation:**

| File | Change |
|------|--------|
| New: `migrations/003_rbac.sql` | `roles`, `user_roles`, `role_permissions` tables |
| New: `core/authz.py` | `check_permission(user_id, action, resource)` -- called before `save_bypass()`, policy writes |
| `data/db.py` | `save_bypass()` calls `check_permission(invoked_by, 'verdict.override', request_id)` |
| `core/config.py` | Add `auth_provider: str` (local, OIDC, SAML) |
| New: `src/eedom/auth/` | OIDC/SAML adapter for SSO integration |

**Audit trail:** Every bypass already creates a `bypass_records` row. Add `approved_by`, `approval_chain` (for multi-party approval), and `expires_at` (time-boxed overrides).

---

## 7. Compliance

### SOC 2

| Control | Current Status | Gap |
|---------|---------------|-----|
| CC6.1 — Access control | No RBAC | Need auth + RBAC (Section 6) |
| CC6.2 — Logical access | CLI trusts caller identity | Need OIDC/SAML SSO |
| CC7.1 — System monitoring | structlog everywhere | Need centralized log aggregation (ELK/Datadog) |
| CC7.2 — Anomaly detection | None | Need alerting on bypass frequency, policy override patterns |
| CC8.1 — Change management | Release Please workflow | Need approval gates on policy changes |
| A1.1 — Availability | Single instance | Need HA (Section 4) |

**Evidence chain** is strong: SHA-256 sealed evidence bundles (`core/seal.py`) with append-only Parquet audit log (`data/parquet_writer.py`). The `verify_seal()` function can detect tampering. This directly supports SOC 2 CC8.1 change management controls.

### ISO 27001

Annex A controls requiring attention:

| Control | Gap |
|---------|-----|
| A.5.15 — Access control | No RBAC |
| A.8.9 — Configuration management | Policies in files, not centrally managed |
| A.8.15 — Logging | structlog present but not centrally aggregated |
| A.8.24 — Cryptography | Evidence seals use SHA-256; consider adding HMAC with a key management service for non-repudiation |

### FedRAMP

FedRAMP requires:

| Requirement | Current | Required Change |
|-------------|---------|-----------------|
| FIPS 140-2 crypto | SHA-256 (compliant algorithm) | Must use FIPS-validated module (OpenSSL FIPS provider) |
| Boundary definition | None | Document system boundary, all data flows |
| Continuous monitoring | None | Deploy to FedRAMP-authorized infrastructure (AWS GovCloud, Azure Gov) |
| Air-gapped operation | Container image downloads binaries at build time | Pre-build and sign images in a connected environment, transfer to air-gapped |
| Data residency | Evidence on local filesystem | Must stay within authorization boundary |

**Air-gapped deployment considerations:**

The `Dockerfile` downloads scanner binaries from GitHub at build time. In an air-gapped environment:
1. Build the image in a connected staging environment
2. Export with `podman save eedom:latest > eedom.tar`
3. Transfer to air-gapped network
4. Load with `podman load < eedom.tar`
5. All vulnerability databases (Trivy, OSV) must be mirrored internally

**OPA policies** must be bundled into the image or served from an internal bundle server. The current `COPY policies/` approach works for air-gapped.

**ClamAV signatures** (`Dockerfile` line 215: `RUN mkdir -p /var/lib/clamav`) are not baked in -- they must be provided via an internal mirror or volume mount.

---

## 8. Integrations

### SIEM (Splunk, Sentinel, Elastic)

Eedom uses structlog throughout. To integrate:

| Approach | Change |
|----------|--------|
| Log-based | Configure structlog JSON renderer -> ship via Fluentd/Vector to SIEM. Zero code change. |
| Event-based | New: `data/siem_client.py` — HTTP POST to SIEM REST API on every `ReviewDecision`. Called from `pipeline.py` after `db.save_decision()` |
| Parquet export | SIEM ingests `decisions.parquet` on a schedule (DuckDB -> CSV -> SIEM bulk import) |

The Parquet schema in `parquet_writer.py:26-56` already contains all fields a SIEM needs: decision, severity counts, triggered rules, advisory IDs, timestamps.

### Jira

Create a Jira ticket on `reject` verdicts:

| File | Change |
|------|--------|
| New: `data/jira_client.py` | httpx POST to Jira REST API v3 |
| `core/pipeline.py` | After `assemble_decision()`, if verdict is `reject`, call `jira_client.create_issue()` |
| `core/config.py` | Add `jira_url`, `jira_project`, `jira_api_token: SecretStr` |

### Slack

Notify channels on policy violations:

| File | Change |
|------|--------|
| New: `data/slack_client.py` | httpx POST to Slack webhook URL |
| `core/pipeline.py` | After `generate_memo()`, if `should_comment`, call `slack_client.post_message()` |
| `core/config.py` | Add `slack_webhook_url: SecretStr | None` |

### Webhook (Generic)

For maximum flexibility, add a generic webhook system:

| File | Change |
|------|--------|
| New: `data/webhook_client.py` | POST `ReviewDecision` JSON to configured URLs with HMAC signing |
| `core/config.py` | Add `webhook_urls: list[str]`, `webhook_secret: SecretStr | None` |
| `core/pipeline.py` | Fire webhooks after evidence is sealed |

---

## 9. Deployment Models

### On-Premise (Self-Hosted Runner)

This is the current model. The `gatekeeper.yml` workflow runs on `self-hosted` runners.

**Architecture:**
```
[GitHub.com] --webhook--> [Self-hosted runner] --scan--> [Repo checkout]
                               |
                               v
                          [eedom container]
                               |
                               v
                          [Postgres (on-prem)]
                               |
                               v
                          [Evidence (NFS/local)]
```

**Sizing per runner:**
- CPU: 4 cores minimum (4 scanner binaries run in parallel via `ThreadPoolExecutor`)
- RAM: 8 GB (Trivy DB + Semgrep rules + Python runtime)
- Disk: 20 GB base + 1 GB per 100 repos of evidence
- Network: Outbound to GitHub API (for PR comments), PyPI (for metadata), vulnerability databases

### Private Cloud (Kubernetes)

Deploy eedom as a Kubernetes workload:

```yaml
# eedom-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: eedom-worker
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: eedom
        image: ghcr.io/<org>/eedom:latest
        resources:
          requests: { cpu: "2", memory: "4Gi" }
          limits:   { cpu: "4", memory: "8Gi" }
        env:
        - name: EEDOM_DB_DSN
          valueFrom:
            secretKeyRef: { name: eedom-secrets, key: db-dsn }
```

**Required additions:**
- Kubernetes CronJob for `mark_vuln_stale()` (weekly cache invalidation)
- PersistentVolumeClaim or S3 for evidence storage
- Postgres operator (CloudNativePG or Zalando) for HA database
- Network policies to restrict egress to known endpoints

### Air-Gapped

No internet access. All external dependencies pre-loaded:

| Dependency | Air-Gap Strategy |
|-----------|-----------------|
| Scanner binaries | Baked into container image (already done in `Dockerfile`) |
| Trivy vulnerability DB | Internal mirror, volume-mounted at `/opt/trivy-db/` |
| OSV database | Internal mirror, pass `--local-db-path` to osv-scanner |
| ClamAV signatures | Internal mirror, volume-mounted at `/var/lib/clamav/` |
| PyPI metadata | Internal PyPI mirror (devpi/Artifactory), configure `EEDOM_PYPI_URL` |
| OPA policies | Bundled in image or served from internal bundle server |
| Container image | Transferred via `podman save`/`podman load` or internal registry |

**New config fields needed in `core/config.py`:**
```python
pypi_base_url: str = "https://pypi.org"  # override for internal mirror
trivy_db_path: str | None = None         # local DB path
osv_db_path: str | None = None           # local DB path
clamav_db_path: str = "/var/lib/clamav"  # signature directory
```

---

## 10. Phased Implementation Plan

### Phase 1: Foundation (Weeks 1-4)

**Goal:** Multi-tenancy + distributed scanning + HA Postgres

| Task | Files | Effort |
|------|-------|--------|
| Add `tenant_id` to all tables with RLS | New: `migrations/003_multi_tenancy.sql` | 3 days |
| Set `app.tenant_id` in DB sessions | `data/db.py`, `data/catalog.py` | 2 days |
| Add `tenant_id` to `EedomSettings` | `core/config.py` | 1 day |
| Implement scan queue worker | New: `src/eedom/worker/scanner_worker.py` | 5 days |
| Integrate catalog cache into pipeline | `core/pipeline.py` | 3 days |
| Partition Parquet writes | `data/parquet_writer.py` | 2 days |
| Deploy HA Postgres (Patroni or RDS) | Infrastructure | 3 days |
| Move evidence to shared storage (NFS/EFS) | `core/config.py` (evidence_path) | 1 day |

### Phase 2: Access Control (Weeks 5-8)

**Goal:** RBAC + SSO + audit trail improvements

| Task | Files | Effort |
|------|-------|--------|
| RBAC schema + migration | New: `migrations/004_rbac.sql` | 2 days |
| Authorization module | New: `core/authz.py` | 3 days |
| SSO adapter (OIDC) | New: `src/eedom/auth/oidc.py` | 5 days |
| Bypass approval workflow | `data/db.py` (extend `save_bypass`) | 3 days |
| Centralized policy DB table | New: `migrations/005_policy_management.sql` | 2 days |
| Policy hierarchy merge logic | New: `core/policy_hierarchy.py` | 3 days |
| Integrate with OPA evaluator | `core/policy.py` | 2 days |

### Phase 3: Integrations + Compliance (Weeks 9-12)

**Goal:** SIEM, Jira, Slack, compliance documentation

| Task | Files | Effort |
|------|-------|--------|
| Generic webhook client | New: `data/webhook_client.py` | 3 days |
| Jira integration | New: `data/jira_client.py` | 3 days |
| Slack integration | New: `data/slack_client.py` | 2 days |
| SIEM log shipping (structlog -> Fluentd) | Infrastructure config | 2 days |
| SOC 2 evidence documentation | Docs | 5 days |
| Air-gapped deployment guide | Docs + config changes in `core/config.py` | 3 days |
| FedRAMP boundary documentation | Docs | 5 days |
| FIPS 140-2 OpenSSL configuration | `core/seal.py`, container image | 2 days |

### Phase 4: Scale (Weeks 13-16)

**Goal:** Kubernetes deployment, 1000-repo readiness

| Task | Files | Effort |
|------|-------|--------|
| Kubernetes manifests | New: `deploy/k8s/` | 3 days |
| Helm chart | New: `deploy/helm/eedom/` | 5 days |
| Horizontal pod autoscaler for workers | Kubernetes config | 2 days |
| Connection pool scaling (PgBouncer) | Infrastructure | 2 days |
| OPA daemon mode (HTTP instead of subprocess) | `core/policy.py` | 3 days |
| Monitoring dashboards (Grafana) | Infrastructure | 3 days |
| Load testing (100/1000 concurrent pipelines) | New: `tests/load/` | 5 days |
| Separate DB per tenant option | New: `data/tenant_router.py` | 3 days |

---

## 11. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| RLS misconfiguration exposes cross-tenant data | Critical | Automated RLS tests in CI; penetration testing |
| Parquet corruption under concurrent writes | High | Partition by run_id (Phase 1) |
| Scanner binary supply chain compromise | High | SHA-256 verification already in Dockerfile; add Sigstore/cosign |
| Air-gapped vulnerability DB staleness | Medium | Automated weekly sync job with alerting on age |
| HNSW index rebuild blocks writes | Medium | Schedule `REINDEX CONCURRENTLY` during maintenance windows |
| Connection pool exhaustion under load | Medium | PgBouncer + connection limit monitoring (Phase 4) |
