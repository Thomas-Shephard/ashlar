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
