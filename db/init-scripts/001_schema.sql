\connect purplegrid;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE TABLE IF NOT EXISTS scan_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_url        TEXT NOT NULL,
    branch          TEXT NOT NULL DEFAULT 'main',
    scan_depth      TEXT NOT NULL DEFAULT 'full',
    status          TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    risk_score      NUMERIC(4,2),
    total_vulns     INTEGER,
    duration_ms     INTEGER,
    raw_payload     JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_results_user_id
    ON scan_results (user_id);

CREATE INDEX IF NOT EXISTS idx_scan_results_status_created
    ON scan_results (status, created_at DESC);

COMMENT ON TABLE users IS
    'Registered user accounts. Passwords stored as bcrypt hashes only.';

COMMENT ON TABLE scan_results IS
    'Every vulnerability scan request and its structured result payload.';