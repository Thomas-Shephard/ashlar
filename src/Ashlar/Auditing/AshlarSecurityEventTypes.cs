namespace Ashlar.Auditing;

/// <summary>
/// Stable event type names emitted by Ashlar security flows.
/// </summary>
public static class AshlarSecurityEventTypes
{
    /// <summary>
    /// Defines the authentication succeeded value.
    /// </summary>
    public const string AuthenticationSucceeded = "ashlar.authentication.succeeded";
    /// <summary>
    /// Defines the authentication failed value.
    /// </summary>
    public const string AuthenticationFailed = "ashlar.authentication.failed";
    /// <summary>
    /// Defines the user created value.
    /// </summary>
    public const string UserCreated = "ashlar.user.created";
    /// <summary>
    /// Defines the credential linked value.
    /// </summary>
    public const string CredentialLinked = "ashlar.credential.linked";
    /// <summary>
    /// Defines the credential consumed value.
    /// </summary>
    public const string CredentialConsumed = "ashlar.credential.consumed";
    /// <summary>
    /// Defines the credential update persisted value.
    /// </summary>
    public const string CredentialUpdatePersisted = "ashlar.credential.updated";
    /// <summary>
    /// Defines the credential update failed value.
    /// </summary>
    public const string CredentialUpdateFailed = "ashlar.credential.update_failed";
    /// <summary>
    /// Defines the email code requested value.
    /// </summary>
    public const string EmailCodeRequested = "ashlar.email_code.requested";
    /// <summary>
    /// Defines the email code request suppressed value.
    /// </summary>
    public const string EmailCodeRequestSuppressed = "ashlar.email_code.request_suppressed";
    /// <summary>
    /// Defines the email code request rate limited value.
    /// </summary>
    public const string EmailCodeRequestRateLimited = "ashlar.email_code.request_rate_limited";
    /// <summary>
    /// Defines the email code verification rate limited value.
    /// </summary>
    public const string EmailCodeVerificationRateLimited = "ashlar.email_code.verification_rate_limited";
    /// <summary>
    /// Defines the magic link requested value.
    /// </summary>
    public const string MagicLinkRequested = "ashlar.magic_link.requested";
    /// <summary>
    /// Defines the magic link request suppressed value.
    /// </summary>
    public const string MagicLinkRequestSuppressed = "ashlar.magic_link.request_suppressed";
    /// <summary>
    /// Defines the magic link request rate limited value.
    /// </summary>
    public const string MagicLinkRequestRateLimited = "ashlar.magic_link.request_rate_limited";
    /// <summary>
    /// Defines the magic link verification rate limited value.
    /// </summary>
    public const string MagicLinkVerificationRateLimited = "ashlar.magic_link.verification_rate_limited";
    /// <summary>
    /// Defines the recovery codes generated value.
    /// </summary>
    public const string RecoveryCodesGenerated = "ashlar.recovery_codes.generated";
    /// <summary>
    /// Defines the recovery codes revoked value.
    /// </summary>
    public const string RecoveryCodesRevoked = "ashlar.recovery_codes.revoked";
    /// <summary>
    /// Defines the recovery code verification rate limited value.
    /// </summary>
    public const string RecoveryCodeVerificationRateLimited = "ashlar.recovery_codes.verification_rate_limited";
    /// <summary>
    /// Defines the session created value.
    /// </summary>
    public const string SessionCreated = "ashlar.session.created";
    /// <summary>
    /// Defines the session validated value.
    /// </summary>
    public const string SessionValidated = "ashlar.session.validated";
    /// <summary>
    /// Defines the session validation failed value.
    /// </summary>
    public const string SessionValidationFailed = "ashlar.session.validation_failed";
    /// <summary>
    /// Defines the session expired value.
    /// </summary>
    public const string SessionExpired = "ashlar.session.expired";
    /// <summary>
    /// Defines the session revoked value.
    /// </summary>
    public const string SessionRevoked = "ashlar.session.revoked";
    /// <summary>
    /// Defines the sessions revoked for user value.
    /// </summary>
    public const string SessionsRevokedForUser = "ashlar.session.revoked_for_user";
    /// <summary>
    /// Defines the invitation created value.
    /// </summary>
    public const string InvitationCreated = "ashlar.invitation.created";
    /// <summary>
    /// Defines the invitation accepted value.
    /// </summary>
    public const string InvitationAccepted = "ashlar.invitation.accepted";
    /// <summary>
    /// Defines the invitation revoked value.
    /// </summary>
    public const string InvitationRevoked = "ashlar.invitation.revoked";
    /// <summary>
    /// Defines the invitation rate limited value.
    /// </summary>
    public const string InvitationRateLimited = "ashlar.invitation.rate_limited";
    /// <summary>
    /// Defines the authentication handshake created value.
    /// </summary>
    public const string AuthenticationHandshakeCreated = "ashlar.authentication.handshake.created";
    /// <summary>
    /// Defines the authentication handshake factor verified value.
    /// </summary>
    public const string AuthenticationHandshakeFactorVerified = "ashlar.authentication.handshake.factor_verified";
    /// <summary>
    /// Defines the authentication handshake completed value.
    /// </summary>
    public const string AuthenticationHandshakeCompleted = "ashlar.authentication.handshake.completed";
    /// <summary>
    /// Defines the authentication handshake revoked value.
    /// </summary>
    public const string AuthenticationHandshakeRevoked = "ashlar.authentication.handshake.revoked";
    /// <summary>
    /// Defines the authentication handshake expired value.
    /// </summary>
    public const string AuthenticationHandshakeExpired = "ashlar.authentication.handshake.expired";
    /// <summary>
    /// Defines the authentication handshake failed value.
    /// </summary>
    public const string AuthenticationHandshakeFailed = "ashlar.authentication.handshake.failed";
    /// <summary>
    /// Defines the authentication handshake verification rate limited value.
    /// </summary>
    public const string AuthenticationHandshakeVerificationRateLimited = "ashlar.authentication.handshake.verification_rate_limited";
    /// <summary>
    /// Defines the authorization grant created value.
    /// </summary>
    public const string AuthorizationGrantCreated = "ashlar.authorization.grant.created";
    /// <summary>
    /// Defines the authorization grant revoked value.
    /// </summary>
    public const string AuthorizationGrantRevoked = "ashlar.authorization.grant.revoked";
    /// <summary>
    /// Defines the totp enrollment started value.
    /// </summary>
    public const string TotpEnrollmentStarted = "ashlar.totp.enrollment_started";
    /// <summary>
    /// Defines the totp enrollment completed value.
    /// </summary>
    public const string TotpEnrollmentCompleted = "ashlar.totp.enrollment_completed";
    /// <summary>
    /// Defines the totp disabled value.
    /// </summary>
    public const string TotpDisabled = "ashlar.totp.disabled";
    /// <summary>
    /// Defines the totp verification rate limited value.
    /// </summary>
    public const string TotpVerificationRateLimited = "ashlar.totp.verification_rate_limited";
    /// <summary>
    /// Defines the bootstrap invitation created value.
    /// </summary>
    public const string BootstrapInvitationCreated = "ashlar.bootstrap.invitation.created";
    /// <summary>
    /// Defines the bootstrap completed value.
    /// </summary>
    public const string BootstrapCompleted = "ashlar.bootstrap.completed";
    /// <summary>
    /// Defines the email verification requested value.
    /// </summary>
    public const string EmailVerificationRequested = "ashlar.email_verification.requested";
    /// <summary>
    /// Defines the email verified value.
    /// </summary>
    public const string EmailVerified = "ashlar.email_verification.verified";
    /// <summary>
    /// Defines the email verification failed value.
    /// </summary>
    public const string EmailVerificationFailed = "ashlar.email_verification.failed";
    /// <summary>
    /// Defines the email verification rate limited value.
    /// </summary>
    public const string EmailVerificationRateLimited = "ashlar.email_verification.rate_limited";
    /// <summary>
    /// Defines the email verification verification rate limited value.
    /// </summary>
    public const string EmailVerificationVerificationRateLimited = "ashlar.email_verification.verification_rate_limited";
    /// <summary>
    /// Defines the email change requested value.
    /// </summary>
    public const string EmailChangeRequested = "ashlar.email_change.requested";
    /// <summary>
    /// Defines the email change request suppressed value.
    /// </summary>
    public const string EmailChangeRequestSuppressed = "ashlar.email_change.request_suppressed";
    /// <summary>
    /// Defines the email changed value.
    /// </summary>
    public const string EmailChanged = "ashlar.email_change.changed";
    /// <summary>
    /// Defines the email change failed value.
    /// </summary>
    public const string EmailChangeFailed = "ashlar.email_change.failed";
    /// <summary>
    /// Defines the email change rate limited value.
    /// </summary>
    public const string EmailChangeRateLimited = "ashlar.email_change.rate_limited";
    /// <summary>
    /// Defines the email change verification rate limited value.
    /// </summary>
    public const string EmailChangeVerificationRateLimited = "ashlar.email_change.verification_rate_limited";
}
