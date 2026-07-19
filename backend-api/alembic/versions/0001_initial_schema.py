"""Initial schema — users, refresh_tokens, scan_results

Revision ID: 0001
Revises:
Create Date: 2026-07-19
"""
from __future__ import annotations

import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(320) NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false,
            replaced_by VARCHAR(64)
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            repo_url TEXT NOT NULL,
            branch VARCHAR(255) NOT NULL DEFAULT 'main',
            scan_depth VARCHAR(16) NOT NULL DEFAULT 'full',
            status VARCHAR(16) NOT NULL CHECK (status IN ('pending','completed','failed')),
            risk_score NUMERIC(5,2),
            total_vulns INTEGER,
            raw_payload JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users (email)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_user_id ON scan_results (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_status_created ON scan_results (status, created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS scan_results CASCADE")
    op.execute("DROP TABLE IF EXISTS refresh_tokens CASCADE")
    op.execute("DROP TABLE IF EXISTS users CASCADE")