CREATE TABLE IF NOT EXISTS ashlar_users (
    id UUID PRIMARY KEY,
    display_email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    name TEXT,
    account_state TEXT NOT NULL DEFAULT 'active',
    tenant_id UUID,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    CONSTRAINT ck_ashlar_users_account_state CHECK (account_state IN ('active', 'disabled', 'locked', 'suspended'))
);

-- NOTE: Requires PostgreSQL 15+ for NULLS NOT DISTINCT support in unique indexes
CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_users_normalized_email_tenant ON ashlar_users (normalized_email, tenant_id) NULLS NOT DISTINCT;

CREATE INDEX IF NOT EXISTS ix_ashlar_users_tenant_id ON ashlar_users (tenant_id);

CREATE OR REPLACE FUNCTION ashlar_prevent_user_tenant_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'User tenant cannot be changed.'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'ashlar_users_tenant_immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_ashlar_users_tenant_immutable
BEFORE UPDATE OF tenant_id ON ashlar_users
FOR EACH ROW EXECUTE FUNCTION ashlar_prevent_user_tenant_change();

CREATE OR REPLACE FUNCTION ashlar_enforce_user_tenant_match()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ashlar_users
        WHERE id = NEW.user_id
          AND tenant_id IS DISTINCT FROM NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'Referenced user tenant does not match row tenant.'
            USING ERRCODE = '23514',
                  CONSTRAINT = TG_TABLE_NAME || '_user_tenant_match';
    END IF;

    RETURN NEW;
END;
$$;

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
    CONSTRAINT ak_ashlar_credentials_identity UNIQUE (provider_type, provider_name, provider_key),
    CONSTRAINT ck_ashlar_credentials_status CHECK (status IN (0, 1)),
    CONSTRAINT ck_ashlar_credentials_revocation_state CHECK (
        (status = 0 AND revoked_at IS NULL) OR (status = 1 AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_user_id ON ashlar_credentials (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_active_user_provider_created ON ashlar_credentials (user_id, provider_type, provider_name, created_at DESC, id)
WHERE revoked_at IS NULL AND status = 0;
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_active_provider_key ON ashlar_credentials (provider_type, provider_name, provider_key, user_id)
WHERE revoked_at IS NULL AND status = 0;
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_expires_at ON ashlar_credentials (expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_credentials_revoked_at ON ashlar_credentials (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_account_lockouts (
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    provider_type TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    failed_attempt_count INTEGER NOT NULL,
    first_failed_at TIMESTAMPTZ NOT NULL,
    last_failed_at TIMESTAMPTZ NOT NULL,
    locked_until TIMESTAMPTZ,
    version TEXT NOT NULL,
    CONSTRAINT ak_ashlar_account_lockouts_identity UNIQUE NULLS NOT DISTINCT (user_id, tenant_id, provider_type, provider_name),
    CONSTRAINT ck_ashlar_account_lockouts_count_positive CHECK (failed_attempt_count > 0),
    CONSTRAINT ck_ashlar_account_lockouts_failure_order CHECK (last_failed_at >= first_failed_at),
    CONSTRAINT ck_ashlar_account_lockouts_lock_after_failure CHECK (locked_until IS NULL OR locked_until > last_failed_at),
    CONSTRAINT ck_ashlar_account_lockouts_provider_not_blank CHECK (length(btrim(provider_type)) > 0 AND length(btrim(provider_name)) > 0)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_user_id ON ashlar_account_lockouts (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_tenant_id ON ashlar_account_lockouts (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_locked_until ON ashlar_account_lockouts (locked_until) WHERE locked_until IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_account_lockouts_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_account_lockouts
FOR EACH ROW EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

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
    CONSTRAINT ck_ashlar_authorization_grants_role_or_permission_not_blank CHECK (
        (role IS NULL OR length(btrim(role)) > 0) AND (permission IS NULL OR length(btrim(permission)) > 0)
    ),
    CONSTRAINT ck_ashlar_authorization_grants_scope CHECK (
        (scope_type IS NULL AND scope_id IS NULL) OR (scope_type IS NOT NULL AND scope_id IS NOT NULL)
    ),
    CONSTRAINT ck_ashlar_authorization_grants_scope_not_blank CHECK (
        (scope_type IS NULL OR length(btrim(scope_type)) > 0) AND (scope_id IS NULL OR length(btrim(scope_id)) > 0)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_user_id ON ashlar_authorization_grants (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_user_created ON ashlar_authorization_grants (user_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_tenant_id ON ashlar_authorization_grants (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_scope ON ashlar_authorization_grants (scope_type, scope_id) WHERE scope_type IS NOT NULL AND scope_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_active_user_scope ON ashlar_authorization_grants (user_id, tenant_id, scope_type, scope_id, created_at DESC, id)
WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_expires_at ON ashlar_authorization_grants (expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_authorization_grants_revoked_at ON ashlar_authorization_grants (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_authorization_grants_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_authorization_grants
FOR EACH ROW EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

CREATE TABLE IF NOT EXISTS ashlar_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    authenticated_at TIMESTAMPTZ,
    primary_provider_type TEXT,
    primary_provider_name TEXT,
    additional_verification_at TIMESTAMPTZ,
    additional_verification_provider_type TEXT,
    additional_verification_provider_name TEXT,
    additional_verification_factor TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB,
    CONSTRAINT ck_ashlar_sessions_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_sessions_revocation_reason_requires_revocation CHECK (revocation_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_id ON ashlar_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_created ON ashlar_sessions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_expires_at ON ashlar_sessions (expires_at) INCLUDE (id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_active_user_created ON ashlar_sessions (user_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_revoked_at ON ashlar_sessions (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_sessions_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_sessions
FOR EACH ROW EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

CREATE TABLE IF NOT EXISTS ashlar_remembered_mfa_devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    token_selector TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    CONSTRAINT ck_ashlar_remembered_mfa_devices_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_remembered_mfa_devices_revocation_reason_requires_revocation CHECK (revocation_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_user_id ON ashlar_remembered_mfa_devices (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_active_user_created ON ashlar_remembered_mfa_devices (user_id, tenant_id, created_at DESC, id)
WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_expires_at ON ashlar_remembered_mfa_devices (expires_at, id, user_id)
WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_revoked_at ON ashlar_remembered_mfa_devices (revoked_at)
WHERE revoked_at IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_remembered_mfa_devices_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_remembered_mfa_devices
FOR EACH ROW EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

CREATE TABLE IF NOT EXISTS ashlar_rate_limits (
    purpose TEXT NOT NULL,
    rate_limit_key TEXT NOT NULL,
    count INTEGER NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    blocked_until TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (purpose, rate_limit_key),
    CONSTRAINT ck_ashlar_rate_limits_count_non_negative CHECK (count >= 0),
    CONSTRAINT ck_ashlar_rate_limits_expiry_after_window_start CHECK (expires_at >= window_start)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_rate_limits_expires_at ON ashlar_rate_limits (expires_at);

CREATE TABLE IF NOT EXISTS ashlar_invitations (
    id UUID PRIMARY KEY,
    display_email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    tenant_id UUID,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB,
    version TEXT NOT NULL,
    CONSTRAINT ck_ashlar_invitations_terminal_state CHECK (accepted_at IS NULL OR revoked_at IS NULL),
    CONSTRAINT ck_ashlar_invitations_expiry_after_creation CHECK (expires_at >= created_at)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_normalized_email_tenant ON ashlar_invitations (normalized_email, tenant_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_active_normalized_email_tenant ON ashlar_invitations (normalized_email, tenant_id)
WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_expires_at ON ashlar_invitations (expires_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_accepted_at ON ashlar_invitations (accepted_at) WHERE accepted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_invitations_revoked_at ON ashlar_invitations (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_security_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    user_id UUID,
    tenant_id UUID,
    actor_user_id UUID,
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
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_user_type_time ON ashlar_security_events (user_id, event_type, occurred_at DESC)
WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_tenant_id ON ashlar_security_events (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_actor_user_id ON ashlar_security_events (actor_user_id) WHERE actor_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_mfa_handshakes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    required_factors JSONB NOT NULL,
    verified_factors JSONB NOT NULL,
    metadata JSONB,
    CONSTRAINT ck_ashlar_mfa_handshakes_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_mfa_handshakes_revoked_state CHECK (
        (is_revoked = FALSE AND revoked_at IS NULL) OR (is_revoked = TRUE AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT ck_ashlar_mfa_handshakes_completed_state CHECK (
        (is_completed = FALSE AND completed_at IS NULL) OR (is_completed = TRUE AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_user_id ON ashlar_mfa_handshakes (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_tenant_user_id ON ashlar_mfa_handshakes (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_expires_at ON ashlar_mfa_handshakes (expires_at) WHERE is_revoked = FALSE AND is_completed = FALSE;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_completed_at ON ashlar_mfa_handshakes (completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_revoked_at ON ashlar_mfa_handshakes (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_mfa_handshakes_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_mfa_handshakes
FOR EACH ROW EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

CREATE TABLE IF NOT EXISTS ashlar_passkey_challenges (
    id UUID PRIMARY KEY,
    version TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user_id UUID REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id UUID,
    handshake_token_hash TEXT,
    factor_type TEXT,
    display_name TEXT,
    registration_proof_type TEXT,
    registration_proof_session_id UUID,
    registration_proof_expires_at TIMESTAMPTZ,
    challenge TEXT NOT NULL UNIQUE,
    options_json JSONB NOT NULL,
    relying_party_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT ck_ashlar_passkey_challenges_purpose CHECK (purpose IN ('passkey-registration', 'passkey-authentication')),
    CONSTRAINT ck_ashlar_passkey_challenges_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_passkey_challenges_registration_user CHECK (purpose <> 'passkey-registration' OR user_id IS NOT NULL),
    CONSTRAINT ck_ashlar_passkey_challenges_registration_proof CHECK (purpose <> 'passkey-registration' OR (registration_proof_type IN ('fresh-mfa', 'fresh-primary') AND registration_proof_session_id IS NOT NULL AND registration_proof_expires_at IS NOT NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_nonregistration_proof CHECK (purpose = 'passkey-registration' OR (registration_proof_type IS NULL AND registration_proof_session_id IS NULL AND registration_proof_expires_at IS NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_factor_binding CHECK ((handshake_token_hash IS NULL AND factor_type IS NULL) OR (handshake_token_hash IS NOT NULL AND factor_type IS NOT NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_factor_shape CHECK (handshake_token_hash IS NULL OR (purpose = 'passkey-authentication' AND user_id IS NOT NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_nonblank_fields CHECK (btrim(version) <> '' AND btrim(purpose) <> '' AND btrim(challenge) <> '' AND btrim(relying_party_id) <> '' AND btrim(origin) <> '' AND (handshake_token_hash IS NULL OR btrim(handshake_token_hash) <> '') AND (factor_type IS NULL OR btrim(factor_type) <> '') AND (display_name IS NULL OR (btrim(display_name) <> '' AND char_length(display_name) <= 100)) AND (registration_proof_type IS NULL OR btrim(registration_proof_type) <> ''))
);

CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_active_expires ON ashlar_passkey_challenges (expires_at, id)
WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_consumed_at ON ashlar_passkey_challenges (consumed_at, id)
WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_user_id ON ashlar_passkey_challenges (user_id)
WHERE user_id IS NOT NULL;

CREATE OR REPLACE TRIGGER trg_ashlar_passkey_challenges_user_tenant_match
BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ashlar_passkey_challenges
FOR EACH ROW
WHEN (NEW.purpose = 'passkey-registration')
EXECUTE FUNCTION ashlar_enforce_user_tenant_match();

CREATE TABLE IF NOT EXISTS ashlar_email_outbox (
    id UUID PRIMARY KEY,
    to_address TEXT NOT NULL,
    from_address TEXT,
    reply_to_address TEXT,
    cc_address TEXT,
    bcc_address TEXT,
    subject TEXT NOT NULL,
    text_body TEXT,
    html_body TEXT,
    sensitivity TEXT NOT NULL DEFAULT 'Normal',
    body_protection TEXT NOT NULL DEFAULT 'None',
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
    discarded_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT ck_ashlar_email_outbox_sensitivity CHECK (sensitivity IN ('Normal', 'ContainsLiveSecret')),
    CONSTRAINT ck_ashlar_email_outbox_body_protection CHECK (body_protection IN ('None', 'SecretProtector')),
    CONSTRAINT ck_ashlar_email_outbox_sensitive_body_protection CHECK (
        sensitivity <> 'ContainsLiveSecret' OR body_protection = 'SecretProtector'
    ),
    CONSTRAINT ck_ashlar_email_outbox_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT ck_ashlar_email_outbox_terminal_state CHECK (
        sent_at IS NULL OR (failed_at IS NULL AND discarded_at IS NULL)
    ),
    CONSTRAINT ck_ashlar_email_outbox_lock_state CHECK (
        (locked_until IS NULL AND locked_by IS NULL) OR (locked_until IS NOT NULL AND locked_by IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_pending ON ashlar_email_outbox (available_at, id)
WHERE sent_at IS NULL AND failed_at IS NULL AND discarded_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_created_at ON ashlar_email_outbox (created_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_locked_until ON ashlar_email_outbox (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_sent_at ON ashlar_email_outbox (sent_at) WHERE sent_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_failed_at ON ashlar_email_outbox (failed_at) WHERE failed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_discarded_at ON ashlar_email_outbox (discarded_at) WHERE discarded_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_sensitive_sent_at ON ashlar_email_outbox (sent_at, id)
WHERE sensitivity = 'ContainsLiveSecret' AND sent_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_email_outbox_sensitive_failed_at ON ashlar_email_outbox (failed_at, id)
WHERE sensitivity = 'ContainsLiveSecret' AND failed_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_security_event_webhook_outbox (
    id UUID PRIMARY KEY,
    endpoint_name TEXT NOT NULL,
    uri TEXT NOT NULL,
    event_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    timeout_ms BIGINT NOT NULL,
    body BYTEA NOT NULL,
    headers JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    locked_until TIMESTAMPTZ,
    locked_by TEXT,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    discarded_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    CONSTRAINT ck_ashlar_security_event_webhook_outbox_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT ck_ashlar_security_event_webhook_outbox_timeout_positive CHECK (timeout_ms > 0),
    CONSTRAINT ck_ashlar_security_event_webhook_outbox_terminal_state CHECK (
        sent_at IS NULL OR (failed_at IS NULL AND discarded_at IS NULL)
    ),
    CONSTRAINT ck_ashlar_security_event_webhook_outbox_lock_state CHECK (
        (locked_until IS NULL AND locked_by IS NULL) OR (locked_until IS NOT NULL AND locked_by IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_pending ON ashlar_security_event_webhook_outbox (available_at, id)
WHERE sent_at IS NULL AND failed_at IS NULL AND discarded_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_created_at ON ashlar_security_event_webhook_outbox (created_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_locked_until ON ashlar_security_event_webhook_outbox (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_sent_at ON ashlar_security_event_webhook_outbox (sent_at) WHERE sent_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_failed_at ON ashlar_security_event_webhook_outbox (failed_at) WHERE failed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_discarded_at ON ashlar_security_event_webhook_outbox (discarded_at) WHERE discarded_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_event_webhook_outbox_event ON ashlar_security_event_webhook_outbox (event_id, event_type);

CREATE TABLE IF NOT EXISTS ashlar_bootstrap_state (
    id INTEGER PRIMARY KEY DEFAULT 1,
    is_initialized BOOLEAN NOT NULL DEFAULT FALSE,
    initialized_at TIMESTAMPTZ,
    initialized_by UUID REFERENCES ashlar_users (id),
    CONSTRAINT singleton_bootstrap_state CHECK (id = 1)
);
