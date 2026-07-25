CREATE TABLE IF NOT EXISTS ashlar_users (
    id TEXT PRIMARY KEY,
    display_email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    name TEXT,
    account_state TEXT NOT NULL DEFAULT 'active' CHECK (account_state IN ('active', 'disabled', 'locked', 'suspended')),
    tenant_id TEXT,
    email_verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_users_normalized_email_tenant
ON ashlar_users (normalized_email, tenant_id)
WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_users_normalized_email_no_tenant
ON ashlar_users (normalized_email)
WHERE tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_ashlar_users_tenant_id ON ashlar_users (tenant_id);

CREATE TRIGGER IF NOT EXISTS trg_ashlar_users_tenant_immutable
BEFORE UPDATE OF tenant_id ON ashlar_users
FOR EACH ROW
WHEN OLD.tenant_id IS NOT NEW.tenant_id
BEGIN
    SELECT RAISE(ABORT, 'ashlar_users tenant cannot be changed');
END;

CREATE TABLE IF NOT EXISTS ashlar_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    provider_key TEXT NOT NULL,
    version TEXT NOT NULL,
    credential_value TEXT,
    metadata TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    expires_at TEXT,
    revoked_at TEXT,
    status INTEGER NOT NULL CHECK (status IN (0, 1)),
    purpose TEXT,
    CONSTRAINT ak_ashlar_credentials_identity UNIQUE (provider_type, provider_name, provider_key),
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
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    provider_type TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    failed_attempt_count INTEGER NOT NULL CHECK (failed_attempt_count > 0),
    first_failed_at TEXT NOT NULL,
    last_failed_at TEXT NOT NULL,
    locked_until TEXT,
    version TEXT NOT NULL,
    CONSTRAINT ck_ashlar_account_lockouts_failure_order CHECK (last_failed_at >= first_failed_at),
    CONSTRAINT ck_ashlar_account_lockouts_lock_after_failure CHECK (locked_until IS NULL OR locked_until > last_failed_at),
    CONSTRAINT ck_ashlar_account_lockouts_provider_not_blank CHECK (trim(provider_type) <> '' AND trim(provider_name) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_account_lockouts_tenant_identity
ON ashlar_account_lockouts (user_id, tenant_id, provider_type, provider_name)
WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ak_ashlar_account_lockouts_global_identity
ON ashlar_account_lockouts (user_id, provider_type, provider_name)
WHERE tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_user_id ON ashlar_account_lockouts (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_tenant_id ON ashlar_account_lockouts (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_account_lockouts_locked_until ON ashlar_account_lockouts (locked_until) WHERE locked_until IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_account_lockouts_user_tenant_match_insert
BEFORE INSERT ON ashlar_account_lockouts
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_account_lockouts user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_account_lockouts_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_account_lockouts
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_account_lockouts user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_authorization_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    scope_type TEXT,
    scope_id TEXT,
    role TEXT,
    permission TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    metadata TEXT,
    CONSTRAINT ck_ashlar_authorization_grants_role_or_permission CHECK (
        (role IS NOT NULL AND permission IS NULL) OR (role IS NULL AND permission IS NOT NULL)
    ),
    CONSTRAINT ck_ashlar_authorization_grants_scope CHECK (
        (scope_type IS NULL AND scope_id IS NULL) OR (scope_type IS NOT NULL AND scope_id IS NOT NULL)
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

CREATE TRIGGER IF NOT EXISTS trg_ashlar_authorization_grants_user_tenant_match_insert
BEFORE INSERT ON ashlar_authorization_grants
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_authorization_grants user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_authorization_grants_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_authorization_grants
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_authorization_grants user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    authenticated_at TEXT,
    primary_provider_type TEXT,
    primary_provider_name TEXT,
    additional_verification_at TEXT,
    additional_verification_provider_type TEXT,
    additional_verification_provider_name TEXT,
    additional_verification_factor TEXT,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata TEXT,
    CONSTRAINT ck_ashlar_sessions_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_sessions_revocation_reason_requires_revocation CHECK (revocation_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_id ON ashlar_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_user_created ON ashlar_sessions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_expires_at ON ashlar_sessions (expires_at, id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_active_user_created ON ashlar_sessions (user_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_sessions_revoked_at ON ashlar_sessions (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_sessions_user_tenant_match_insert
BEFORE INSERT ON ashlar_sessions
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_sessions user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_sessions_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_sessions
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_sessions user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_remembered_mfa_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    token_selector TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    display_name TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    CONSTRAINT ck_ashlar_remembered_mfa_devices_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_remembered_mfa_devices_revocation_reason_requires_revocation CHECK (revocation_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_user_id ON ashlar_remembered_mfa_devices (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_active_user_created ON ashlar_remembered_mfa_devices (user_id, tenant_id, created_at DESC, id)
WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_expires_at ON ashlar_remembered_mfa_devices (expires_at, id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_remembered_mfa_devices_revoked_at ON ashlar_remembered_mfa_devices (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_remembered_mfa_devices_user_tenant_match_insert
BEFORE INSERT ON ashlar_remembered_mfa_devices
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_remembered_mfa_devices user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_remembered_mfa_devices_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_remembered_mfa_devices
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_remembered_mfa_devices user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_rate_limits (
    purpose TEXT NOT NULL,
    rate_limit_key TEXT NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 0),
    window_start TEXT NOT NULL,
    blocked_until TEXT,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (purpose, rate_limit_key),
    CONSTRAINT ck_ashlar_rate_limits_expiry_after_window_start CHECK (expires_at >= window_start)
);

CREATE INDEX IF NOT EXISTS ix_ashlar_rate_limits_expires_at ON ashlar_rate_limits (expires_at);

CREATE TABLE IF NOT EXISTS ashlar_invitations (
    id TEXT PRIMARY KEY,
    display_email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    tenant_id TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    revoked_at TEXT,
    metadata TEXT,
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
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    user_id TEXT,
    tenant_id TEXT,
    actor_user_id TEXT,
    session_id TEXT,
    provider_type TEXT,
    provider_name TEXT,
    ip_address TEXT,
    user_agent TEXT,
    correlation_id TEXT,
    outcome TEXT,
    failure_reason TEXT,
    properties TEXT
);

CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_occurred_at ON ashlar_security_events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_user_id ON ashlar_security_events (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_user_type_time ON ashlar_security_events (user_id, event_type, occurred_at DESC)
WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_tenant_id ON ashlar_security_events (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_security_events_actor_user_id ON ashlar_security_events (actor_user_id) WHERE actor_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ashlar_mfa_handshakes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    is_completed INTEGER NOT NULL DEFAULT 0 CHECK (is_completed IN (0, 1)),
    revoked_at TEXT,
    completed_at TEXT,
    required_factors TEXT NOT NULL,
    verified_factors TEXT NOT NULL,
    metadata TEXT,
    CONSTRAINT ck_ashlar_mfa_handshakes_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_mfa_handshakes_revoked_state CHECK (
        (is_revoked = 0 AND revoked_at IS NULL) OR (is_revoked = 1 AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT ck_ashlar_mfa_handshakes_completed_state CHECK (
        (is_completed = 0 AND completed_at IS NULL) OR (is_completed = 1 AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_user_id ON ashlar_mfa_handshakes (user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_tenant_user_id ON ashlar_mfa_handshakes (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_expires_at ON ashlar_mfa_handshakes (expires_at) WHERE is_revoked = 0 AND is_completed = 0;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_completed_at ON ashlar_mfa_handshakes (completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_mfa_handshakes_revoked_at ON ashlar_mfa_handshakes (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_mfa_handshakes_user_tenant_match_insert
BEFORE INSERT ON ashlar_mfa_handshakes
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_mfa_handshakes user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_mfa_handshakes_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_mfa_handshakes
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_mfa_handshakes user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_passkey_challenges (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user_id TEXT REFERENCES ashlar_users (id) ON DELETE CASCADE,
    tenant_id TEXT,
    handshake_token_hash TEXT,
    factor_type TEXT,
    display_name TEXT,
    registration_proof_type TEXT,
    registration_proof_session_id TEXT,
    registration_proof_expires_at TEXT,
    challenge TEXT NOT NULL UNIQUE,
    options_json TEXT NOT NULL,
    relying_party_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CONSTRAINT ck_ashlar_passkey_challenges_purpose CHECK (purpose IN ('passkey-registration', 'passkey-authentication')),
    CONSTRAINT ck_ashlar_passkey_challenges_expiry_after_creation CHECK (expires_at >= created_at),
    CONSTRAINT ck_ashlar_passkey_challenges_registration_user CHECK (purpose <> 'passkey-registration' OR user_id IS NOT NULL),
    CONSTRAINT ck_ashlar_passkey_challenges_registration_proof CHECK (purpose <> 'passkey-registration' OR (registration_proof_type IN ('fresh-mfa', 'fresh-primary') AND registration_proof_session_id IS NOT NULL AND registration_proof_expires_at IS NOT NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_nonregistration_proof CHECK (purpose = 'passkey-registration' OR (registration_proof_type IS NULL AND registration_proof_session_id IS NULL AND registration_proof_expires_at IS NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_factor_binding CHECK ((handshake_token_hash IS NULL AND factor_type IS NULL) OR (handshake_token_hash IS NOT NULL AND factor_type IS NOT NULL)),
    CONSTRAINT ck_ashlar_passkey_challenges_factor_shape CHECK (handshake_token_hash IS NULL OR (purpose = 'passkey-authentication' AND user_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_active_expires ON ashlar_passkey_challenges (expires_at, id)
WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_consumed_at ON ashlar_passkey_challenges (consumed_at, id)
WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ashlar_passkey_challenges_user_id ON ashlar_passkey_challenges (user_id)
WHERE user_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_passkey_challenges_user_tenant_match_insert
BEFORE INSERT ON ashlar_passkey_challenges
FOR EACH ROW
WHEN NEW.purpose = 'passkey-registration' AND EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_passkey_challenges user tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_ashlar_passkey_challenges_user_tenant_match_update
BEFORE UPDATE OF user_id, tenant_id ON ashlar_passkey_challenges
FOR EACH ROW
WHEN NEW.purpose = 'passkey-registration' AND EXISTS (
    SELECT 1
    FROM ashlar_users
    WHERE id = NEW.user_id
      AND tenant_id IS NOT NEW.tenant_id
)
BEGIN
    SELECT RAISE(ABORT, 'ashlar_passkey_challenges user tenant mismatch');
END;

CREATE TABLE IF NOT EXISTS ashlar_email_outbox (
    id TEXT PRIMARY KEY,
    to_address TEXT NOT NULL,
    from_address TEXT,
    reply_to_address TEXT,
    cc_address TEXT,
    bcc_address TEXT,
    subject TEXT NOT NULL,
    text_body TEXT,
    html_body TEXT,
    sensitivity TEXT NOT NULL,
    body_protection TEXT NOT NULL DEFAULT 'None',
    headers TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    locked_until TEXT,
    locked_by TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_attempt_at TEXT,
    sent_at TEXT,
    failed_at TEXT,
    discarded_at TEXT,
    last_error TEXT,
    CONSTRAINT ck_ashlar_email_outbox_sensitivity CHECK (sensitivity IN ('Normal', 'ContainsLiveSecret')),
    CONSTRAINT ck_ashlar_email_outbox_body_protection CHECK (body_protection IN ('None', 'SecretProtector')),
    CONSTRAINT ck_ashlar_email_outbox_sensitive_body_protection CHECK (
        sensitivity = 'Normal' OR body_protection = 'SecretProtector'
    ),
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
    id TEXT PRIMARY KEY,
    endpoint_name TEXT NOT NULL,
    uri TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms > 0),
    body BLOB NOT NULL,
    headers TEXT NOT NULL,
    created_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    locked_until TEXT,
    locked_by TEXT,
    sent_at TEXT,
    failed_at TEXT,
    discarded_at TEXT,
    last_attempt_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error TEXT,
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
    is_initialized INTEGER NOT NULL DEFAULT 0 CHECK (is_initialized IN (0, 1)),
    initialized_at TEXT,
    initialized_by TEXT REFERENCES ashlar_users (id),
    CONSTRAINT singleton_bootstrap_state CHECK (id = 1)
);
