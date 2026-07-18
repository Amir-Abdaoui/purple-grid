-- Purple-Grid · Database Schema · Phase 1
-- Run automatically by postgres:alpine on first container start.

-- Ensure we're in the right database
\connect purplegrid;

-- Extension: gen_random_uuid() — prefer pgcrypto for UUID generation over app-layer.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- scan_results — persists every scan request and its outcome.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_url        TEXT        NOT NULL,
    branch          TEXT        NOT NULL DEFAULT 'main',
    scan_depth      TEXT        NOT NULL DEFAULT 'full',
    status          TEXT        NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    risk_score      NUMERIC(4,2),
    total_vulns     INTEGER,
    raw_payload     JSONB,          -- Full scan result for auditability.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- Index: most queries filter by status and order by created_at.
CREATE INDEX IF NOT EXISTS idx_scan_results_status_created
    ON scan_results (status, created_at DESC);

-- Index: allow fast lookup by repository URL (for history views).
CREATE INDEX IF NOT EXISTS idx_scan_results_repo_url
    ON scan_results (repo_url);

COMMENT ON TABLE scan_results IS
    'Stores every vulnerability scan request and its structured result payload.';