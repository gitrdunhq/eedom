-- 002_package_catalog.sql
-- Org-wide package catalog with semantic search (pgvector)
-- Decouples scanning from PR evaluation — scan once, look up instantly.
--
-- Requires: CREATE EXTENSION vector;  (run once as superuser)

BEGIN;

-- Enable pgvector if not already present
CREATE EXTENSION IF NOT EXISTS vector;

-- ─── Org-wide package catalog ──────────────────────────────────────────
-- One row per unique (ecosystem, package_name, version).
-- Shared across all repos — scan once, serve everywhere.

CREATE TABLE IF NOT EXISTS package_catalog (
    catalog_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem           TEXT NOT NULL,
    package_name        TEXT NOT NULL,
    version             TEXT NOT NULL,

    -- PyPI metadata (cached, rarely changes for a given version)
    summary             TEXT,
    author              TEXT,
    license             TEXT,
    source_url          TEXT,
    first_published_at  TIMESTAMPTZ,
    package_age_days    INTEGER,
    transitive_dep_count INTEGER,

    -- Semantic search: embedding of summary + package name
    description_embedding vector(1536),

    -- Scan state
    sbom_path           TEXT,
    sbom_scanned_at     TIMESTAMPTZ,
    vuln_scanned_at     TIMESTAMPTZ,
    license_scanned_at  TIMESTAMPTZ,
    vuln_finding_count  INTEGER NOT NULL DEFAULT 0,
    vuln_max_severity   TEXT CHECK (vuln_max_severity IN ('critical', 'high', 'medium', 'low', 'info', NULL)),
    license_findings    JSONB NOT NULL DEFAULT '[]',

    -- Latest OPA decision for this package version
    latest_decision     TEXT CHECK (latest_decision IN ('approve', 'reject', 'needs_review', 'approve_with_constraints', NULL)),
    latest_decision_at  TIMESTAMPTZ,
    policy_version      TEXT,

    -- Lifecycle
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deprecated', 'restricted', 'quarantine')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (ecosystem, package_name, version)
);

-- ─── Repo inventory ────────────────────────────────────────────────────
-- Tracks which packages each repo uses. Updated on push to main.

CREATE TABLE IF NOT EXISTS repo_inventory (
    inventory_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_name       TEXT NOT NULL,
    branch          TEXT NOT NULL DEFAULT 'main',
    lockfile_path   TEXT NOT NULL,
    lockfile_hash   TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (repo_name, lockfile_path)
);

-- Join table: which packages are in which repo
CREATE TABLE IF NOT EXISTS repo_packages (
    repo_name       TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    scope           TEXT NOT NULL DEFAULT 'runtime',
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (repo_name, ecosystem, package_name, version)
);

-- ─── Scan queue ────────────────────────────────────────────────────────
-- Packages that need scanning (new or stale). Workers pull from this.

CREATE TABLE IF NOT EXISTS scan_queue (
    queue_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    scan_type       TEXT NOT NULL CHECK (scan_type IN ('full', 'vuln_only', 'rescan')),
    priority        INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    requested_by    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- ─── Indexes ───────────────────────────────────────────────────────────

-- Package catalog lookups
CREATE INDEX IF NOT EXISTS idx_catalog_ecosystem_pkg_ver
    ON package_catalog (ecosystem, package_name, version);

CREATE INDEX IF NOT EXISTS idx_catalog_vuln_severity
    ON package_catalog (vuln_max_severity) WHERE vuln_max_severity IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_catalog_status
    ON package_catalog (status);

CREATE INDEX IF NOT EXISTS idx_catalog_vuln_scanned
    ON package_catalog (vuln_scanned_at);

CREATE INDEX IF NOT EXISTS idx_catalog_latest_decision
    ON package_catalog (latest_decision);

-- Semantic search (HNSW index for fast approximate nearest neighbor)
CREATE INDEX IF NOT EXISTS idx_catalog_embedding
    ON package_catalog USING hnsw (description_embedding vector_cosine_ops);

-- Repo inventory lookups
CREATE INDEX IF NOT EXISTS idx_repo_packages_pkg
    ON repo_packages (ecosystem, package_name, version);

CREATE INDEX IF NOT EXISTS idx_repo_packages_repo
    ON repo_packages (repo_name);

-- Scan queue: pending items by priority
CREATE INDEX IF NOT EXISTS idx_scan_queue_pending
    ON scan_queue (priority DESC, created_at ASC) WHERE status = 'pending';

COMMIT;
