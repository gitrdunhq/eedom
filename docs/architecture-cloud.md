# Cloud SaaS Architecture Assessment

Evaluation of eedom for cloud-native SaaS deployment.

Based on: `ARCHITECTURE.md`, `src/eedom/core/config.py`, `src/eedom/core/pipeline.py`,
`src/eedom/core/orchestrator.py`, `src/eedom/data/db.py`, `src/eedom/data/catalog.py`,
`src/eedom/data/evidence.py`, `src/eedom/data/parquet_writer.py`, `Dockerfile`,
`docker-compose.yml`, and `.github/workflows/`.

---

## 1. Current State vs. SaaS Requirements

| SaaS Requirement | Current State | Gap |
|-----------------|---------------|-----|
| Webhook-driven execution | GitHub Action on self-hosted runner (`gatekeeper.yml`) | No HTTP listener, no GitHub App, no webhook receiver |
| Queue-based async processing | `scan_queue` table exists (`002_package_catalog.sql`), no worker | Need worker process, dead-letter queue, retry |
| Object storage for evidence | Local filesystem (`evidence.py:37`, `root_path: str`) | Need S3/GCS adapter |
| Multi-tenant data isolation | Zero tenant awareness anywhere | Need tenant isolation at every layer |
| REST API | CLI only (`cli/main.py`) | Need HTTP API surface |
| Horizontal scaling | Single-process `ThreadPoolExecutor` (`orchestrator.py:50`) | Need distributed task execution |
| Billing/metering | None | Need usage tracking per tenant |
| Dashboard | Parquet file on disk (`parquet_writer.py`) | Need queryable analytics API |

---

## 2. GitHub App Webhook Model vs. Self-Hosted Runner

### Current: Self-Hosted Runner

The `gatekeeper.yml` workflow triggers on `pull_request` events matching dependency and source file paths. It runs on a `self-hosted` runner, checks out the repo, generates a diff, and executes eedom inline.

**Limitations for SaaS:**
- Requires customers to configure self-hosted runners
- No centralized control plane
- Each customer installation is independent
- No shared scanning cache across customers

### Target: GitHub App Webhook Model

```
[GitHub.com]
    |
    | installation webhook (pull_request.opened/synchronize)
    v
[API Gateway (ALB / Cloud Run)] --> [Webhook Handler]
    |
    | validate signature, extract metadata
    v
[Message Queue (SQS / Cloud Tasks)]
    |
    | fan out per repo
    v
[Scanner Workers (ECS Fargate / Cloud Run Jobs)]
    |
    | clone repo, run pipeline, write results
    v
[Results Writer]
    |
    +---> [Postgres (RDS / Cloud SQL)] -- decisions, catalog
    +---> [Object Storage (S3 / GCS)] -- evidence bundles
    +---> [GitHub API] -- PR comment, check run status
```

**GitHub App permissions needed:**
- `contents: read` (clone repo)
- `pull_requests: write` (post comments)
- `checks: write` (create check runs with SARIF)
- `statuses: write` (set commit status)

**Webhook handler implementation:**

| File | Purpose |
|------|---------|
| New: `src/eedom/api/webhook.py` | Receives `pull_request` events, validates `X-Hub-Signature-256`, extracts repo/PR metadata |
| New: `src/eedom/api/github_app.py` | Manages installation tokens (JWT -> installation access token), repo cloning |
| New: `src/eedom/api/queue_publisher.py` | Publishes scan jobs to SQS/Cloud Tasks |

The existing `ReviewPipeline.evaluate()` (`pipeline.py:73`) remains unchanged -- the webhook handler is a new presentation-tier entry point alongside CLI and GATEKEEPER agent.

---

## 3. Serverless Scanning

### Option A: AWS Lambda + ECS Fargate

Lambda is unsuitable for eedom scanning due to:
- 15-minute max execution time (pipeline timeout is 300s, but scanner binary startup + DB writes can exceed this under load)
- 10 GB max container image size (eedom image with all binaries is ~2 GB, but Lambda cold starts with large images are 10-30 seconds)
- 512 MB `/tmp` limit (Trivy DB alone is ~500 MB)
- No persistent local storage for incremental code graph rebuilds (`blast-radius` plugin uses SQLite at `repo/.eedom/code_graph.sqlite`)

**Recommended: ECS Fargate tasks** (AWS) or **Cloud Run Jobs** (GCP)

```
SQS Queue --> ECS Fargate Task (eedom container)
                |
                +-- Clone repo from GitHub (installation token)
                +-- Run ReviewPipeline.evaluate() or registry.run_all()
                +-- Write evidence to S3
                +-- Write decisions to RDS
                +-- Post PR comment via GitHub API
                +-- Task exits (pay per second)
```

| AWS Service | Role | Config |
|------------|------|--------|
| SQS (Standard) | Scan job queue | Visibility timeout: 600s, DLQ after 3 failures |
| ECS Fargate | Scanner execution | 4 vCPU, 8 GB RAM, 200 GB ephemeral storage |
| RDS PostgreSQL | Decisions + catalog | db.r6g.large, Multi-AZ, pgvector extension |
| S3 | Evidence storage | Bucket per tenant, SSE-S3 encryption, lifecycle policy |
| ECR | Container registry | eedom image, immutable tags |
| ALB | Webhook ingress | HTTPS termination, WAF for rate limiting |
| Secrets Manager | GitHub App private key, DB credentials | Rotated every 90 days |
| CloudWatch | Logging + metrics | structlog JSON -> CloudWatch Logs |

### Option B: GCP Cloud Run + Cloud Tasks

| GCP Service | Role | Config |
|------------|------|--------|
| Cloud Tasks | Scan job queue | Max dispatch rate: 500/s, retry with backoff |
| Cloud Run Jobs | Scanner execution | 4 vCPU, 8 GiB RAM, 300s timeout |
| Cloud SQL PostgreSQL | Decisions + catalog | db-custom-4-16384, HA, pgvector |
| GCS | Evidence storage | Bucket per tenant, CMEK encryption |
| Artifact Registry | Container registry | eedom image |
| Cloud Load Balancing | Webhook ingress | HTTPS, Cloud Armor for WAF |
| Secret Manager | GitHub App private key, DB credentials | Automatic rotation |
| Cloud Logging | Logging | structlog JSON -> Cloud Logging |

### Scanner Binary Considerations

The current `Dockerfile` installs scanner binaries (Syft, Trivy, OSV-Scanner, OPA, Gitleaks) as static Go binaries. These work unchanged in Fargate/Cloud Run since the container image is the same. No repackaging needed.

Trivy and OSV-Scanner need vulnerability database access:
- **Trivy:** Use `TRIVY_DB_REPOSITORY` env var to point to an internal OCI registry mirror. In serverless, pre-warm the DB in a shared EFS/Filestore mount.
- **OSV-Scanner:** API mode (default) requires outbound HTTPS. For isolated networks, use `--experimental-local-db`.

---

## 4. Object Storage for Evidence

### Current: Local Filesystem

`EvidenceStore` (`evidence.py:21`) writes to `Path(root_path) / key / artifact_name` using atomic temp-file + rename. The atomic rename guarantee relies on POSIX same-filesystem semantics.

### Target: S3/GCS with Local Cache

| File | Change |
|------|--------|
| New: `data/evidence_s3.py` | `S3EvidenceStore` implementing same interface as `EvidenceStore`. Uses `boto3` S3 PutObject with `ContentMD5` for integrity. |
| New: `data/evidence_gcs.py` | `GCSEvidenceStore` using `google-cloud-storage`. |
| `data/evidence.py` | Extract `EvidenceStoreProtocol` from current implementation. Add factory: `create_evidence_store(config) -> EvidenceStoreProtocol` |
| `core/config.py` | Add `evidence_backend: str = "filesystem"` (filesystem/s3/gcs), `evidence_bucket: str | None`, `evidence_prefix: str = ""` |
| `core/pipeline.py` | No change -- already uses `EvidenceStore` through constructor injection |

**S3 layout per tenant:**

```
s3://eedom-evidence-{region}/
  {tenant_id}/
    {short_sha}/{YYYYMMDDHHmm}/
      {package_name}/
        decision.json
        memo.md
      seal.json
    decisions/
      year=2026/month=04/
        decisions-{run_id}.parquet
```

**Seal chain adaptation:** `create_seal()` (`core/seal.py`) currently walks the local filesystem. For S3, the seal must be computed locally from the objects being uploaded, then the seal itself uploaded. `find_previous_seal_hash()` needs an S3 list + download of the most recent `seal.json`.

---

## 5. Queue-Based Processing

### Architecture

```
Webhook Handler
    |
    v
[Scan Job Queue]  <-- SQS Standard / Cloud Tasks
    |
    | Message: { tenant_id, repo, pr_number, commit_sha, installation_id }
    v
[Scanner Worker Pool]  <-- ECS Fargate / Cloud Run Jobs
    |
    | 1. Acquire GitHub installation token
    | 2. Clone repo (shallow, specific SHA)
    | 3. Check PackageCatalog for cached results
    | 4. Run ScanOrchestrator for uncached packages
    | 5. Update PackageCatalog
    | 6. Run OPA policy evaluation
    | 7. Write evidence to S3
    | 8. Write decision to RDS
    | 9. Post PR comment
    v
[Dead Letter Queue]  <-- failures after 3 retries
    |
    v
[DLQ Processor]  <-- alert + create incident
```

### Idempotency

The pipeline must be idempotent -- the same webhook delivered twice should not produce duplicate PR comments or corrupt evidence.

**Current idempotency gaps:**
- `db.py:save_request()` does a blind INSERT. Re-processing the same PR event creates duplicate rows.
- `evidence.py:store()` overwrites existing files (atomic rename). This is accidentally idempotent.
- `parquet_writer.py:append_decisions()` appends without dedup. Re-processing creates duplicate rows.
- PR comment posting in `gatekeeper.yml` does check for an existing comment marker (`<!-- eedom-review -->`) and updates it -- this is idempotent.

**Fixes needed:**

| File | Change |
|------|--------|
| `data/db.py` | Change `save_request()` to `INSERT ... ON CONFLICT (request_id) DO NOTHING` |
| `data/parquet_writer.py` | Add `run_id` dedup: skip append if `run_id` already exists in the file |
| New: `core/idempotency.py` | Idempotency key = `sha256(tenant_id + repo + pr_number + head_sha)`. Check before processing. |

### Dead Letter Queue

Messages that fail 3 times go to DLQ. A DLQ processor:
1. Logs the failure with full context
2. Creates an internal incident
3. Posts a "scan failed" comment on the PR so the developer knows
4. Fires a webhook to the tenant's configured alerting endpoint

---

## 6. Multi-Region

### Data Residency

| Data Type | Residency Requirement | Storage |
|-----------|----------------------|---------|
| Source code (cloned repos) | Ephemeral, never persisted | Worker ephemeral storage, deleted after scan |
| Evidence bundles | Must stay in tenant's chosen region | S3/GCS bucket per region |
| Decisions + catalog | Must stay in tenant's chosen region | RDS/Cloud SQL per region |
| Parquet audit logs | Must stay in tenant's chosen region | S3/GCS per region |

### Multi-Region Architecture

```
                    [Global API Gateway]
                    (Route53 / Cloud DNS)
                         |
              +----------+----------+
              |                     |
        [us-east-1]           [eu-west-1]
              |                     |
    +----+----+----+      +----+----+----+
    |    |         |      |    |         |
   ALB  SQS   RDS(primary)  ALB  SQS   RDS(primary)
    |    |         |      |    |         |
  Fargate Workers  S3   Fargate Workers  GCS
```

Each region is a fully independent deployment. No cross-region data flow. Tenant signup assigns a home region. The global API gateway routes webhooks to the correct region based on tenant mapping.

**Postgres cross-region:** Do NOT use cross-region replication for tenant data. Each region has its own RDS instance. The `package_catalog` table can be replicated read-only across regions since vulnerability data is not tenant-specific.

---

## 7. Billing and Metering

### Usage Dimensions

| Dimension | Source | Metering Point |
|-----------|--------|---------------|
| Repos scanned | Webhook handler | Count unique `repo` per billing period |
| Scans executed | Worker completion | Count `scan_queue.status = 'completed'` per tenant |
| Plugins used per scan | `PluginResult` list length | Sum of active plugins across all scans |
| Evidence storage (GB) | S3/GCS bucket metrics | Per-tenant bucket size |
| Seats (users with access) | Auth system | Count unique `user_id` per tenant |

### Implementation

| File | Change |
|------|--------|
| New: `data/metering.py` | `MeteringClient` that records events to a metering backend (Stripe Billing, Lago, or custom) |
| New: `migrations/006_metering.sql` | `usage_events` table: `(tenant_id, event_type, quantity, timestamp)` |
| `core/pipeline.py` | After pipeline completes, emit `scan_completed` metering event |
| Worker | Emit `repo_scanned` event on each webhook processed |

**Billing tiers:**

| Tier | Repos | Scans/month | Evidence retention | Price signal |
|------|-------|-------------|-------------------|-------------|
| Free | 3 | 100 | 7 days | $0 |
| Team | 25 | 2,500 | 90 days | Low |
| Business | 100 | 25,000 | 1 year | Medium |
| Enterprise | Unlimited | Unlimited | Custom | Custom |

Evidence retention is enforced via S3 lifecycle policies per tenant. `EedomSettings` gains `evidence_retention_days: int = 90`.

---

## 8. Tenant Isolation for Code Scanning

### Threat Model

Eedom clones and scans customer source code. A SaaS deployment must guarantee:
1. No cross-tenant code access
2. Scanned code is ephemeral (deleted after scan)
3. Scanner plugins cannot exfiltrate code to external endpoints
4. Workers cannot access other tenants' evidence or database rows

### Isolation Strategy

**Compute isolation:** Each scan runs in its own Fargate task or Cloud Run job. No shared filesystem between tasks. Ephemeral storage is destroyed when the task exits.

**Network isolation:** Workers run in a private subnet with:
- Egress only to: GitHub API (for cloning + PR comments), PyPI API (for metadata), vulnerability databases (Trivy/OSV), internal RDS, internal S3
- No egress to arbitrary internet endpoints
- Network policy / security group enforces the allowlist
- Semgrep plugin must NOT phone home to Semgrep servers (use `--metrics=off`)

**Data isolation:**
- RLS on all database tables (see enterprise doc Section 2)
- S3 bucket policy restricts each worker's IAM role to the current tenant's prefix
- Workers receive a short-lived IAM role scoped to one tenant via STS AssumeRole

**Code lifecycle:**

```
1. Worker starts
2. Clone repo to ephemeral storage (--depth=1 --single-branch)
3. Run pipeline
4. Write evidence to tenant's S3 prefix
5. Delete clone from ephemeral storage
6. Worker exits, ephemeral storage destroyed
```

The current `orchestrator.py` uses `ThreadPoolExecutor` to run scanners in parallel within a single process. In the SaaS model, this is fine -- the scanner binaries operate on a local clone that exists only in the worker's ephemeral storage.

---

## 9. REST API Surface

### Endpoints

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/webhooks/github` | Receive GitHub App webhooks | HMAC signature |
| GET | `/api/v1/repos` | List repos for tenant | Bearer token |
| GET | `/api/v1/repos/{repo}/decisions` | List decisions for a repo | Bearer token |
| GET | `/api/v1/repos/{repo}/decisions/{id}` | Get decision detail | Bearer token |
| GET | `/api/v1/catalog` | Search package catalog | Bearer token |
| GET | `/api/v1/catalog/{ecosystem}/{name}/{version}` | Package detail | Bearer token |
| POST | `/api/v1/repos/{repo}/scan` | Trigger manual scan | Bearer token |
| GET | `/api/v1/policies` | List org policies | Bearer token (admin) |
| PUT | `/api/v1/policies/{id}` | Update policy | Bearer token (admin) |
| POST | `/api/v1/bypasses` | Create verdict override | Bearer token (approver) |
| GET | `/api/v1/usage` | Billing usage for tenant | Bearer token |
| GET | `/api/v1/health` | Health check | None |

### Implementation

| File | Purpose |
|------|---------|
| New: `src/eedom/api/app.py` | FastAPI application, middleware (auth, tenant context, CORS) |
| New: `src/eedom/api/routes/webhooks.py` | GitHub webhook handler |
| New: `src/eedom/api/routes/decisions.py` | Decision CRUD endpoints |
| New: `src/eedom/api/routes/catalog.py` | Catalog search + detail |
| New: `src/eedom/api/routes/policies.py` | Policy management |
| New: `src/eedom/api/routes/bypasses.py` | Verdict override endpoint |
| New: `src/eedom/api/routes/usage.py` | Metering data |
| New: `src/eedom/api/auth.py` | JWT validation, tenant extraction |

The API is a third presentation-tier entry point alongside `cli/` and `agent/`. It delegates to the same `core/` logic -- no business rules in the API layer.

---

## 10. Dashboard Data

### Analytics Backend

The current `decisions.parquet` file is designed for DuckDB analytics. For SaaS, this becomes a data lake:

```
s3://eedom-analytics-{region}/
  {tenant_id}/
    decisions/
      year=2026/month=04/day=24/
        decisions-{run_id}.parquet
```

**Query engine options:**

| Option | Pros | Cons |
|--------|------|------|
| DuckDB (in-process) | Zero infrastructure, fast on small data | Single-node, no concurrent queries at scale |
| Amazon Athena | Serverless, scales to PB | Cold start 2-5s, per-query cost |
| BigQuery | Serverless, fast, columnar | GCP-only |
| ClickHouse Cloud | Real-time analytics, fast dashboards | Additional infrastructure |

**Recommendation:** Start with Athena/BigQuery for the analytics backend. The Parquet schema in `parquet_writer.py:26-56` is already optimized for columnar queries.

### Dashboard Queries

| Dashboard Widget | Query Pattern |
|-----------------|---------------|
| Decision trend (approve/reject/needs_review over time) | `GROUP BY date_trunc('day', timestamp), decision` |
| Top vulnerable packages | `GROUP BY package_name ORDER BY SUM(vuln_critical + vuln_high) DESC` |
| Mean pipeline duration | `AVG(pipeline_duration_seconds) GROUP BY date_trunc('hour', timestamp)` |
| Policy violation rate | `COUNT(*) FILTER (WHERE decision = 'reject') / COUNT(*)` |
| Scanner reliability | `UNNEST(scanner_names, scanner_statuses) GROUP BY tool, status` |
| Triggered rules heatmap | `UNNEST(triggered_rules) GROUP BY rule, date_trunc('week', timestamp)` |

All of these work directly against the existing Parquet schema with zero schema changes.

---

## 11. Service Decomposition

### What Becomes a Microservice

| Service | Current Location | Why Split |
|---------|-----------------|-----------|
| **Webhook Ingress** | N/A (new) | Must handle bursty traffic independently; scale to 0 when idle |
| **Scanner Worker** | `core/pipeline.py` + `core/orchestrator.py` | CPU/memory intensive; scales independently; runs in ephemeral compute |
| **API Server** | N/A (new) | Serves dashboard + REST API; always-on; different scaling profile than workers |
| **Policy Engine** | `core/policy.py` (OPA subprocess) | Deploy OPA as HTTP service; shared across all workers; policy hot-reload |

### What Stays Monolithic (Shared Library)

| Component | Current Location | Why Keep Together |
|-----------|-----------------|-------------------|
| **Core logic** | `core/models.py`, `core/normalizer.py`, `core/decision.py`, `core/memo.py`, `core/seal.py` | Pure functions with no I/O; shared by all services as a library |
| **Plugin system** | `core/plugin.py`, `core/registry.py`, `plugins/` | Tightly coupled to scanner execution; splitting adds IPC overhead with no benefit |
| **Data layer** | `data/db.py`, `data/catalog.py`, `data/evidence.py` | Shared repository pattern; each service imports what it needs |
| **Renderer** | `core/renderer.py`, `core/sarif.py`, `templates/` | Pure rendering functions; no state |

### Service Architecture

```
                        [GitHub]
                           |
                           v
+--[Webhook Ingress]--+  (Cloud Run / ALB + Lambda)
|  - Validate webhook  |
|  - Extract metadata   |
|  - Publish to queue   |
+-----------+-----------+
            |
            v
+--[Scan Queue]--------+  (SQS / Cloud Tasks)
|  - Priority ordering  |
|  - DLQ after 3 retries|
+-----------+-----------+
            |
            v
+--[Scanner Worker]----+  (ECS Fargate / Cloud Run Jobs)
|  - Clone repo         |
|  - Run pipeline       |  Uses: core/*, data/*, plugins/*
|  - Write evidence     |
|  - Post PR comment    |
+-----------+-----------+
            |
            v
+--[Postgres]-----------+  (RDS / Cloud SQL)
|  - Decisions           |
|  - Catalog             |
|  - Scan queue          |
|  - RBAC                |
+------------------------+
            |
+--[Object Storage]-----+  (S3 / GCS)
|  - Evidence bundles    |
|  - Parquet audit logs  |
+------------------------+

+--[API Server]---------+  (ECS Service / Cloud Run)
|  - REST API            |  Uses: core/*, data/*
|  - Dashboard data      |
|  - Policy management   |
|  - Bypass workflow     |
+------------------------+

+--[OPA Service]--------+  (Sidecar or standalone)
|  - Policy evaluation   |
|  - Bundle server       |
|  - Hot reload          |
+------------------------+
```

### Shared Library: `eedom-core`

The `src/eedom/core/` and `src/eedom/data/` packages become a shared Python library installed in every service's container. The `pyproject.toml` already defines eedom as an installable package. Each service imports what it needs:

```python
# Webhook Ingress
from eedom.api.webhook import handle_github_event

# Scanner Worker
from eedom.core.pipeline import ReviewPipeline
from eedom.core.orchestrator import ScanOrchestrator

# API Server
from eedom.data.db import DecisionRepository
from eedom.data.catalog import PackageCatalog
```

No code duplication. Services share the library; they differ only in their entry point and scaling profile.

---

## 12. Phased Migration Path

### Phase 1: API + Webhook (Weeks 1-6)

**Goal:** GitHub App receiving webhooks, scan jobs enqueued, existing pipeline runs as worker.

| Task | Files | AWS/GCP Service | Effort |
|------|-------|-----------------|--------|
| GitHub App registration | GitHub Developer Settings | N/A | 1 day |
| Webhook handler (FastAPI) | New: `src/eedom/api/webhook.py`, `src/eedom/api/github_app.py` | ALB + Fargate / Cloud Run | 5 days |
| Queue publisher | New: `src/eedom/api/queue_publisher.py` | SQS / Cloud Tasks | 2 days |
| Scanner worker (pulls from queue, runs pipeline) | New: `src/eedom/worker/main.py` | ECS Fargate / Cloud Run Jobs | 5 days |
| S3 evidence store | New: `data/evidence_s3.py` | S3 / GCS | 3 days |
| Evidence store factory + config | `data/evidence.py`, `core/config.py` | N/A | 2 days |
| RDS/Cloud SQL setup | Infrastructure (Terraform/Pulumi) | RDS Multi-AZ / Cloud SQL HA | 3 days |
| Idempotency layer | New: `core/idempotency.py`, changes in `data/db.py` | N/A | 3 days |
| DLQ + alerting | Infrastructure | SQS DLQ + CloudWatch Alarm / Cloud Monitoring | 2 days |

### Phase 2: Multi-Tenancy + API (Weeks 7-12)

**Goal:** Tenant isolation, REST API for external consumption, basic dashboard data.

| Task | Files | AWS/GCP Service | Effort |
|------|-------|-----------------|--------|
| Tenant data model + RLS | `migrations/003_multi_tenancy.sql` | N/A | 3 days |
| Auth middleware (JWT + tenant) | New: `src/eedom/api/auth.py` | Cognito / Firebase Auth | 5 days |
| REST API routes | New: `src/eedom/api/routes/*.py` | N/A | 8 days |
| API server deployment | `src/eedom/api/app.py` | ECS Service / Cloud Run | 3 days |
| Partitioned Parquet writes to S3 | `data/parquet_writer.py` | S3 / GCS | 2 days |
| Analytics query layer | New: `src/eedom/api/analytics.py` | Athena / BigQuery | 3 days |
| Network isolation (VPC/security groups) | Infrastructure | VPC + NACLs + SGs | 3 days |
| IAM role per tenant (STS scoping) | Infrastructure | IAM + STS | 3 days |

### Phase 3: Scale + Billing (Weeks 13-18)

**Goal:** Auto-scaling, metering, billing integration, multi-region foundation.

| Task | Files | AWS/GCP Service | Effort |
|------|-------|-----------------|--------|
| Auto-scaling worker pool | Infrastructure | ECS Auto Scaling / Cloud Run concurrency | 3 days |
| OPA as HTTP service | `core/policy.py` refactor | ECS sidecar / Cloud Run | 3 days |
| Metering system | New: `data/metering.py`, `migrations/006_metering.sql` | N/A | 5 days |
| Stripe/billing integration | New: `src/eedom/api/billing.py` | Stripe API | 5 days |
| Usage dashboards | New: API + frontend | N/A | 8 days |
| Second region deployment | Infrastructure duplication | Full stack in eu-west-1 / europe-west1 | 5 days |
| Global DNS routing | Infrastructure | Route53 / Cloud DNS | 2 days |
| Load testing (1000 concurrent scans) | New: `tests/load/` | N/A | 5 days |

### Phase 4: Polish + Enterprise Features (Weeks 19-24)

**Goal:** SSO, policy management UI, advanced analytics, SOC 2 readiness.

| Task | Files | Effort |
|------|-------|--------|
| SAML/OIDC SSO | New: `src/eedom/auth/` | 8 days |
| Policy management UI | Frontend + API routes | 10 days |
| RBAC for verdict overrides | `core/authz.py`, `data/db.py` | 5 days |
| Advanced analytics (trend detection, anomaly alerts) | Analytics layer | 8 days |
| SOC 2 Type II evidence collection | Ops + docs | 10 days |
| Penetration testing (cross-tenant isolation) | External engagement | 5 days |
| Public documentation + API docs (OpenAPI) | Docs | 5 days |

---

## 13. Cost Estimation (AWS, 100 Tenants)

| Component | Service | Monthly Cost Estimate |
|-----------|---------|----------------------|
| Webhook ingress | ALB + Fargate (0.25 vCPU, 0.5 GB, always-on) | $15 |
| Scanner workers | Fargate Spot (4 vCPU, 8 GB, ~5000 tasks/month x 3 min avg) | $250 |
| Database | RDS db.r6g.large Multi-AZ (2 vCPU, 16 GB) | $400 |
| Evidence storage | S3 Standard (estimated 500 GB, 100K PUTs) | $15 |
| Queue | SQS (5000 messages/month) | $1 |
| Container registry | ECR (5 GB) | $1 |
| Secrets | Secrets Manager (10 secrets) | $5 |
| Logging | CloudWatch Logs (50 GB/month) | $25 |
| DNS + SSL | Route53 + ACM | $5 |
| **Total** | | **~$720/month** |

At 1000 tenants with proportional scaling: ~$3,500/month (workers scale sub-linearly due to catalog cache hits).

---

## 14. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| GitHub App token compromise exposes customer repos | Critical | Short-lived installation tokens (1 hour), minimal permissions, token never stored |
| Cross-tenant data leak via RLS bypass | Critical | Automated RLS tests, penetration testing, separate DB option for regulated tenants |
| Scanner worker exfiltrates source code | High | VPC egress allowlist, no internet access except approved endpoints |
| Parquet corruption during concurrent S3 writes | High | One Parquet file per run (no append), idempotency keys |
| Trivy/OSV DB staleness in serverless (cold cache) | Medium | Pre-warm DB on shared EFS/Filestore, refresh every 6 hours |
| Webhook flood (DDoS via forged webhooks) | Medium | HMAC signature validation, rate limiting at ALB/WAF |
| Cost runaway from large monorepo scans | Medium | Per-scan timeout enforcement (already 300s), per-tenant monthly scan cap |
