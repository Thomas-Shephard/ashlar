namespace Ashlar.Auditing;

/// <summary>
/// Stable event type names emitted by Ashlar security flows.
/// </summary>
public static class AshlarSecurityEventTypes
{
    /// <summary>
    /// Emitted when a primary credential is authenticated successfully.
    /// </summary>
    public const string AuthenticationSucceeded = "ashlar.authentication.succeeded";
    /// <summary>
    /// Emitted when a primary credential authentication attempt fails.
    /// </summary>
    public const string AuthenticationFailed = "ashlar.authentication.failed";
    /// <summary>
    /// Emitted when primary authentication is rejected by rate limiting.
    /// </summary>
    public const string AuthenticationRateLimited = "ashlar.authentication.rate_limited";
    /// <summary>
    /// Emitted when an operator resets an authentication rate-limit bucket.
    /// </summary>
    public const string AuthenticationRateLimitBucketReset = "ashlar.authentication.rate_limit_bucket.reset";
    /// <summary>
    /// Emitted when automatic account lockout is activated for a user and provider.
    /// </summary>
    public const string AccountLockoutActivated = "ashlar.account_lockout.activated";
    /// <summary>
    /// Emitted when stored automatic account lockout state is cleared.
    /// </summary>
    public const string AccountLockoutReset = "ashlar.account_lockout.reset";
    /// <summary>
    /// Emitted when Ashlar creates a user account.
    /// </summary>
    public const string UserCreated = "ashlar.user.created";
    /// <summary>
    /// Emitted when a user's account state is changed.
    /// </summary>
    public const string UserAccountStateChanged = "ashlar.user.account_state_changed";
    /// <summary>
    /// Emitted when credentials are revoked for a user.
    /// </summary>
    public const string UserCredentialsRevoked = "ashlar.user.credentials_revoked";
    /// <summary>
    /// Emitted when MFA artifacts are reset for a user.
    /// </summary>
    public const string UserMfaReset = "ashlar.user.mfa_reset";
    /// <summary>
    /// Emitted when a provider-derived credential is linked to a user.
    /// </summary>
    public const string CredentialLinked = "ashlar.credential.linked";
    /// <summary>
    /// Emitted when a one-time credential is consumed after successful authentication.
    /// </summary>
    public const string CredentialConsumed = "ashlar.credential.consumed";
    /// <summary>
    /// Emitted when provider-requested credential usage or replacement is persisted.
    /// </summary>
    public const string CredentialUpdatePersisted = "ashlar.credential.updated";
    /// <summary>
    /// Emitted when provider-requested credential usage or replacement cannot be persisted.
    /// </summary>
    public const string CredentialUpdateFailed = "ashlar.credential.update_failed";
    /// <summary>
    /// Emitted when an email-code sign-in message is requested.
    /// </summary>
    public const string EmailCodeRequested = "ashlar.email_code.requested";
    /// <summary>
    /// Emitted when an email-code request is accepted but message delivery is suppressed.
    /// </summary>
    public const string EmailCodeRequestSuppressed = "ashlar.email_code.request_suppressed";
    /// <summary>
    /// Emitted when an email-code request is rejected by rate limiting.
    /// </summary>
    public const string EmailCodeRequestRateLimited = "ashlar.email_code.request_rate_limited";
    /// <summary>
    /// Emitted when email-code verification is rejected by rate limiting.
    /// </summary>
    public const string EmailCodeVerificationRateLimited = "ashlar.email_code.verification_rate_limited";
    /// <summary>
    /// Emitted when a magic-link sign-in message is requested.
    /// </summary>
    public const string MagicLinkRequested = "ashlar.magic_link.requested";
    /// <summary>
    /// Emitted when a magic-link request is accepted but message delivery is suppressed.
    /// </summary>
    public const string MagicLinkRequestSuppressed = "ashlar.magic_link.request_suppressed";
    /// <summary>
    /// Emitted when a magic-link request is rejected by rate limiting.
    /// </summary>
    public const string MagicLinkRequestRateLimited = "ashlar.magic_link.request_rate_limited";
    /// <summary>
    /// Emitted when magic-link verification is rejected by rate limiting.
    /// </summary>
    public const string MagicLinkVerificationRateLimited = "ashlar.magic_link.verification_rate_limited";
    /// <summary>
    /// Emitted when recovery codes are generated for a user.
    /// </summary>
    public const string RecoveryCodesGenerated = "ashlar.recovery_codes.generated";
    /// <summary>
    /// Emitted when recovery codes are revoked for a user.
    /// </summary>
    public const string RecoveryCodesRevoked = "ashlar.recovery_codes.revoked";
    /// <summary>
    /// Emitted when Ashlar issues an application session.
    /// </summary>
    public const string SessionCreated = "ashlar.session.created";
    /// <summary>
    /// Emitted when an application session bearer token is validated.
    /// </summary>
    public const string SessionValidated = "ashlar.session.validated";
    /// <summary>
    /// Emitted when an application session is updated with step-up verification metadata.
    /// </summary>
    public const string SessionStepUpVerified = "ashlar.session.step_up_verified";
    /// <summary>
    /// Emitted when application session bearer-token validation fails.
    /// </summary>
    public const string SessionValidationFailed = "ashlar.session.validation_failed";
    /// <summary>
    /// Emitted when application session validation finds an expired session.
    /// </summary>
    public const string SessionExpired = "ashlar.session.expired";
    /// <summary>
    /// Emitted when an application session is revoked.
    /// </summary>
    public const string SessionRevoked = "ashlar.session.revoked";
    /// <summary>
    /// Emitted when application sessions are revoked for a user.
    /// </summary>
    public const string SessionsRevokedForUser = "ashlar.session.revoked_for_user";
    /// <summary>
    /// Emitted when an invitation is created and queued for delivery.
    /// </summary>
    public const string InvitationCreated = "ashlar.invitation.created";
    /// <summary>
    /// Emitted when an invitation is accepted and a user is created or linked.
    /// </summary>
    public const string InvitationAccepted = "ashlar.invitation.accepted";
    /// <summary>
    /// Emitted when an invitation token is previewed without accepting it.
    /// </summary>
    public const string InvitationPreviewed = "ashlar.invitation.previewed";
    /// <summary>
    /// Emitted when pending invitations are revoked.
    /// </summary>
    public const string InvitationRevoked = "ashlar.invitation.revoked";
    /// <summary>
    /// Emitted when invitation creation is rejected by rate limiting.
    /// </summary>
    public const string InvitationRateLimited = "ashlar.invitation.rate_limited";
    /// <summary>
    /// Emitted when an MFA or step-up authentication handshake is created.
    /// </summary>
    public const string AuthenticationHandshakeCreated = "ashlar.authentication.handshake.created";
    /// <summary>
    /// Emitted when a factor challenge in an authentication handshake is verified.
    /// </summary>
    public const string AuthenticationHandshakeFactorVerified = "ashlar.authentication.handshake.factor_verified";
    /// <summary>
    /// Emitted when an authentication handshake is completed.
    /// </summary>
    public const string AuthenticationHandshakeCompleted = "ashlar.authentication.handshake.completed";
    /// <summary>
    /// Emitted when an authentication handshake is revoked.
    /// </summary>
    public const string AuthenticationHandshakeRevoked = "ashlar.authentication.handshake.revoked";
    /// <summary>
    /// Emitted when an authentication handshake is rejected because it expired.
    /// </summary>
    public const string AuthenticationHandshakeExpired = "ashlar.authentication.handshake.expired";
    /// <summary>
    /// Emitted when authentication handshake verification fails.
    /// </summary>
    public const string AuthenticationHandshakeFailed = "ashlar.authentication.handshake.failed";
    /// <summary>
    /// Emitted when authentication handshake verification is rejected by rate limiting.
    /// </summary>
    public const string AuthenticationHandshakeVerificationRateLimited = "ashlar.authentication.handshake.verification_rate_limited";
    /// <summary>
    /// Emitted when an authorization grant is created.
    /// </summary>
    public const string AuthorizationGrantCreated = "ashlar.authorization.grant.created";
    /// <summary>
    /// Emitted when an authorization grant is revoked.
    /// </summary>
    public const string AuthorizationGrantRevoked = "ashlar.authorization.grant.revoked";
    /// <summary>
    /// Emitted when TOTP enrollment starts and a shared secret is generated.
    /// </summary>
    public const string TotpEnrollmentStarted = "ashlar.totp.enrollment_started";
    /// <summary>
    /// Emitted when TOTP enrollment is verified and persisted.
    /// </summary>
    public const string TotpEnrollmentCompleted = "ashlar.totp.enrollment_completed";
    /// <summary>
    /// Emitted when a TOTP credential is disabled.
    /// </summary>
    public const string TotpDisabled = "ashlar.totp.disabled";
    /// <summary>
    /// Emitted when a remembered MFA device token is created.
    /// </summary>
    public const string RememberedMfaDeviceCreated = "ashlar.remembered_mfa_device.created";
    /// <summary>
    /// Emitted when a remembered MFA device token satisfies additional verification.
    /// </summary>
    public const string RememberedMfaDeviceUsed = "ashlar.remembered_mfa_device.used";
    /// <summary>
    /// Emitted when a remembered MFA device token is rejected.
    /// </summary>
    public const string RememberedMfaDeviceRejected = "ashlar.remembered_mfa_device.rejected";
    /// <summary>
    /// Emitted when one remembered MFA device token is revoked.
    /// </summary>
    public const string RememberedMfaDeviceRevoked = "ashlar.remembered_mfa_device.revoked";
    /// <summary>
    /// Emitted when remembered MFA device tokens are revoked for a user.
    /// </summary>
    public const string RememberedMfaDevicesRevoked = "ashlar.remembered_mfa_device.revoked_for_user";
    /// <summary>
    /// Emitted when passkey registration options are created.
    /// </summary>
    public const string PasskeyRegistrationStarted = "ashlar.passkey.registration_started";
    /// <summary>
    /// Emitted when passkey registration is verified and persisted.
    /// </summary>
    public const string PasskeyRegistrationCompleted = "ashlar.passkey.registration_completed";
    /// <summary>
    /// Emitted when passkey authentication options are created.
    /// </summary>
    public const string PasskeyAuthenticationStarted = "ashlar.passkey.authentication_started";
    /// <summary>
    /// Emitted when passkey authentication is verified successfully.
    /// </summary>
    public const string PasskeyAuthenticationCompleted = "ashlar.passkey.authentication_completed";
    /// <summary>
    /// Emitted when a passkey display name is changed.
    /// </summary>
    public const string PasskeyRenamed = "ashlar.passkey.renamed";
    /// <summary>
    /// Emitted when a passkey credential is revoked.
    /// </summary>
    public const string PasskeyRevoked = "ashlar.passkey.revoked";
    /// <summary>
    /// Emitted when first-admin bootstrap setup is requested.
    /// </summary>
    public const string BootstrapRequested = "ashlar.bootstrap.requested";
    /// <summary>
    /// Emitted when first-admin bootstrap completes and the installation is initialized.
    /// </summary>
    public const string BootstrapCompleted = "ashlar.bootstrap.completed";
    /// <summary>
    /// Emitted when an email-verification message is requested.
    /// </summary>
    public const string EmailVerificationRequested = "ashlar.email_verification.requested";
    /// <summary>
    /// Emitted when an email-verification token is accepted and the email is marked verified.
    /// </summary>
    public const string EmailVerified = "ashlar.email_verification.verified";
    /// <summary>
    /// Emitted when email-verification token confirmation fails.
    /// </summary>
    public const string EmailVerificationFailed = "ashlar.email_verification.failed";
    /// <summary>
    /// Emitted when an email-verification request is rejected by rate limiting.
    /// </summary>
    public const string EmailVerificationRateLimited = "ashlar.email_verification.rate_limited";
    /// <summary>
    /// Emitted when email-verification token confirmation is rejected by rate limiting.
    /// </summary>
    public const string EmailVerificationVerificationRateLimited = "ashlar.email_verification.verification_rate_limited";
    /// <summary>
    /// Emitted when an email-change confirmation message is requested.
    /// </summary>
    public const string EmailChangeRequested = "ashlar.email_change.requested";
    /// <summary>
    /// Emitted when an email-change request is accepted but message delivery is suppressed.
    /// </summary>
    public const string EmailChangeRequestSuppressed = "ashlar.email_change.request_suppressed";
    /// <summary>
    /// Emitted when an email-change token is accepted and the email address is updated.
    /// </summary>
    public const string EmailChanged = "ashlar.email_change.changed";
    /// <summary>
    /// Emitted when email-change token confirmation fails.
    /// </summary>
    public const string EmailChangeFailed = "ashlar.email_change.failed";
    /// <summary>
    /// Emitted when an email-change request is rejected by rate limiting.
    /// </summary>
    public const string EmailChangeRateLimited = "ashlar.email_change.rate_limited";
    /// <summary>
    /// Emitted when email-change token confirmation is rejected by rate limiting.
    /// </summary>
    public const string EmailChangeVerificationRateLimited = "ashlar.email_change.verification_rate_limited";
    /// <summary>
    /// Emitted when a password-reset message is requested.
    /// </summary>
    public const string PasswordResetRequested = "ashlar.password_reset.requested";
    /// <summary>
    /// Emitted when a password-reset request is accepted but message delivery is suppressed.
    /// </summary>
    public const string PasswordResetRequestSuppressed = "ashlar.password_reset.request_suppressed";
    /// <summary>
    /// Emitted when a password-reset request is rejected by rate limiting.
    /// </summary>
    public const string PasswordResetRequestRateLimited = "ashlar.password_reset.request_rate_limited";
    /// <summary>
    /// Emitted when a password-reset token is accepted and the credential is changed.
    /// </summary>
    public const string PasswordResetCompleted = "ashlar.password_reset.completed";
    /// <summary>
    /// Emitted when password-reset token confirmation fails.
    /// </summary>
    public const string PasswordResetFailed = "ashlar.password_reset.failed";
    /// <summary>
    /// Emitted when password-reset token confirmation is rejected by rate limiting.
    /// </summary>
    public const string PasswordResetVerificationRateLimited = "ashlar.password_reset.verification_rate_limited";
    /// <summary>
    /// Emitted when a failed email outbox row is restored for dispatcher retry.
    /// </summary>
    public const string EmailOutboxDeliveryRetried = "ashlar.email_outbox.delivery_retried";
    /// <summary>
    /// Emitted when a failed email outbox row is discarded by an operator.
    /// </summary>
    public const string EmailOutboxDeliveryDiscarded = "ashlar.email_outbox.delivery_discarded";
    /// <summary>
    /// Emitted when security-event webhook delivery fails and will be retried.
    /// </summary>
    public const string SecurityEventWebhookOutboxDeliveryRetried = "ashlar.security_event_webhook.outbox.delivery_retried";
    /// <summary>
    /// Emitted when security-event webhook delivery fails and is discarded.
    /// </summary>
    public const string SecurityEventWebhookOutboxDeliveryDiscarded = "ashlar.security_event_webhook.outbox.delivery_discarded";
}

