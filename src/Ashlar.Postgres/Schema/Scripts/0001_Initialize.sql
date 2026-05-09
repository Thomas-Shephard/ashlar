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
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_expires_at ON ashlar_credentials (expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_revoked_at ON ashlar_credentials (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_authorization_grants (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    scope_type TEXT,
    scope_id TEXT,
    role TEXT,
    permission TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB,
    CONSTRAINT ck_ashlar_authorization_grants_role_or_permission CHECK (
        (role IS NOT NULL AND permission IS NULL) OR (role IS NULL AND permission IS NOT NULL)
    ),
    CONSTRAINT ck_ashlar_authorization_grants_scope CHECK (
        (scope_type IS NULL AND scope_id IS NULL) OR (scope_type IS NOT NULL AND scope_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_user_id ON ashlar_authorization_grants (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_tenant_id ON ashlar_authorization_grants (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_scope ON ashlar_authorization_grants (scope_type, scope_id) WHERE scope_type IS NOT NULL AND scope_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_active_user ON ashlar_authorization_grants (user_id, tenant_id, scope_type, scope_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_expires_at ON ashlar_authorization_grants (expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_revoked_at ON ashlar_authorization_grants (revoked_at) WHERE revoked_at IS NOT NULL;

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
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_created ON ashlar_sessions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_expires_at ON ashlar_sessions (expires_at) INCLUDE (id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_active_user_created ON ashlar_sessions (user_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_revoked_at ON ashlar_sessions (revoked_at) WHERE revoked_at IS NOT NULL;

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
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_accepted_at ON ashlar_invitations (accepted_at) WHERE accepted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_revoked_at ON ashlar_invitations (revoked_at) WHERE revoked_at IS NOT NULL;

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

CREATE TABLE IF NOT EXISTS ashlar_mfa_handshakes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    required_factors JSONB NOT NULL,
    verified_factors JSONB NOT NULL,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_user_id ON ashlar_mfa_handshakes (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_expires_at ON ashlar_mfa_handshakes (expires_at) WHERE is_revoked = FALSE AND is_completed = FALSE;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_completed_at ON ashlar_mfa_handshakes (completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_revoked_at ON ashlar_mfa_handshakes (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_email_outbox (
    id UUID PRIMARY KEY,
    to_address TEXT NOT NULL,
    from_address TEXT,
    reply_to_address TEXT,
    subject TEXT NOT NULL,
    text_body TEXT,
    html_body TEXT,
    headers JSONB,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    locked_until TIMESTAMPTZ,
    locked_by TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_pending ON ashlar_email_outbox (available_at)
WHERE sent_at IS NULL AND failed_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_created_at ON ashlar_email_outbox (created_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_locked_until ON ashlar_email_outbox (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_sent_at ON ashlar_email_outbox (sent_at) WHERE sent_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_failed_at ON ashlar_email_outbox (failed_at) WHERE failed_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_bootstrap_state (
    id INTEGER PRIMARY KEY DEFAULT 1,
    is_initialized BOOLEAN NOT NULL DEFAULT FALSE,
    initialized_at TIMESTAMPTZ,
    initialized_by UUID REFERENCES ashlar_users (id),
    CONSTRAINT singleton_bootstrap_state CHECK (id = 1)
);
