-- 001_initial_schema.sql
-- Admission Control PoC — initial database schema
-- Idempotent: safe to run multiple times (CREATE TABLE IF NOT EXISTS inside a transaction)

BEGIN;

-- admission_requests: incoming dependency change requests
CREATE TABLE IF NOT EXISTS admission_requests (
    request_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_type     TEXT NOT NULL CHECK (request_type IN ('new_package', 'upgrade', 'reapproval', 'exception')),
    ecosystem        TEXT NOT NULL,
    package_name     TEXT NOT NULL,
    target_version   TEXT NOT NULL,
    current_version  TEXT,
    team             TEXT NOT NULL,
    scope            TEXT NOT NULL DEFAULT 'runtime',
    pr_url           TEXT,
    pr_number        INTEGER,
    repo_name        TEXT,
    commit_sha       TEXT,
    use_case         TEXT,
    operating_mode   TEXT NOT NULL CHECK (operating_mode IN ('monitor', 'advise')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- scan_results: per-tool scanner output metadata
CREATE TABLE IF NOT EXISTS scan_results (
    scan_result_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id       UUID NOT NULL REFERENCES admission_requests(request_id),
    tool_name        TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('success', 'failed', 'timeout', 'skipped')),
    finding_count    INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    raw_output_path  TEXT,
    message          TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- policy_evaluations: OPA policy verdicts
CREATE TABLE IF NOT EXISTS policy_evaluations (
    evaluation_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id       UUID NOT NULL REFERENCES admission_requests(request_id),
    policy_version   TEXT NOT NULL,
    decision         TEXT NOT NULL CHECK (decision IN ('approve', 'reject', 'needs_review', 'approve_with_constraints')),
    triggered_rules  JSONB NOT NULL DEFAULT '[]',
    constraints      JSONB NOT NULL DEFAULT '[]',
    note             TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- admission_decisions: final pipeline verdict
CREATE TABLE IF NOT EXISTS admission_decisions (
    decision_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id               UUID NOT NULL REFERENCES admission_requests(request_id),
    decision                 TEXT NOT NULL CHECK (decision IN ('approve', 'reject', 'needs_review', 'approve_with_constraints')),
    findings_summary         JSONB NOT NULL DEFAULT '{}',
    evidence_bundle_path     TEXT,
    memo_text                TEXT,
    pipeline_duration_seconds REAL NOT NULL DEFAULT 0,
    operating_mode           TEXT NOT NULL CHECK (operating_mode IN ('monitor', 'advise')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- bypass_records: timeout / manual / kill-switch overrides
CREATE TABLE IF NOT EXISTS bypass_records (
    bypass_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id   UUID REFERENCES admission_requests(request_id),
    bypass_type  TEXT NOT NULL CHECK (bypass_type IN ('timeout', 'manual', 'kill_switch')),
    invoked_by   TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes (IF NOT EXISTS requires PG 9.5+, which PG 16 covers)
CREATE INDEX IF NOT EXISTS idx_admission_requests_ecosystem_package
    ON admission_requests (ecosystem, package_name);

CREATE INDEX IF NOT EXISTS idx_admission_requests_team
    ON admission_requests (team);

CREATE INDEX IF NOT EXISTS idx_admission_requests_created_at
    ON admission_requests (created_at);

CREATE INDEX IF NOT EXISTS idx_admission_decisions_decision
    ON admission_decisions (decision);

CREATE INDEX IF NOT EXISTS idx_admission_decisions_created_at
    ON admission_decisions (created_at);

CREATE INDEX IF NOT EXISTS idx_scan_results_request_id
    ON scan_results (request_id);

CREATE INDEX IF NOT EXISTS idx_policy_evaluations_request_id
    ON policy_evaluations (request_id);

COMMIT;
