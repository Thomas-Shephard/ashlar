CREATE TABLE IF NOT EXISTS ashlar_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    name TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ
);

-- NOTE: Requires PostgreSQL 15+ for NULLS NOT DISTINCT support in unique indexes
CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_users_email_tenant ON ashlar_users (normalized_email, tenant_id) NULLS NOT DISTINCT;


CREATE INDEX IF NOT EXISTS ix_ashlar_users_tenant_id ON ashlar_users (tenant_id);

CREATE TABLE IF NOT EXISTS ashlar_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    provider_key TEXT NOT NULL,
    version TEXT NOT NULL,
    credential_value TEXT,
    metadata TEXT,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    status INTEGER NOT NULL,
    purpose TEXT,
    CONSTRAINT ak_ashlar_credentials_identity UNIQUE (provider_type, provider_name, provider_key)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_user_id ON ashlar_credentials (user_id);

CREATE TABLE IF NOT EXISTS ashlar_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_id ON ashlar_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_expires_at ON ashlar_sessions (expires_at) INCLUDE (id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_active_user ON ashlar_sessions (user_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_cleanup ON ashlar_sessions (expires_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_rate_limits (
    purpose TEXT NOT NULL,
    rate_limit_key TEXT NOT NULL,
    count INTEGER NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    blocked_until TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (purpose, rate_limit_key)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_rate_limits_expires_at ON ashlar_rate_limits (expires_at);

CREATE TABLE IF NOT EXISTS ashlar_invitations (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    tenant_id UUID,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB,
    version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_email_tenant ON ashlar_invitations (normalized_email, tenant_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_expires_at ON ashlar_invitations (expires_at);

CREATE TABLE IF NOT EXISTS ashlar_security_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    user_id UUID,
    session_id UUID,
    provider_type TEXT,
    provider_name TEXT,
    ip_address TEXT,
    user_agent TEXT,
    correlation_id TEXT,
    outcome TEXT,
    failure_reason TEXT,
    properties JSONB
);

CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_occurred_at ON ashlar_security_events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_user_id ON ashlar_security_events (user_id);
