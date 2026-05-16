namespace Ashlar.Auditing;

/// <summary>
/// Stable event type names emitted by Ashlar security flows.
/// </summary>
public static class AshlarSecurityEventTypes
{
    public const string AuthenticationSucceeded = "ashlar.authentication.succeeded";
    public const string AuthenticationFailed = "ashlar.authentication.failed";
    public const string UserCreated = "ashlar.user.created";
    public const string CredentialLinked = "ashlar.credential.linked";
    public const string CredentialConsumed = "ashlar.credential.consumed";
    public const string CredentialUpdatePersisted = "ashlar.credential.updated";
    public const string CredentialUpdateFailed = "ashlar.credential.update_failed";
    public const string EmailCodeRequested = "ashlar.email_code.requested";
    public const string EmailCodeRequestSuppressed = "ashlar.email_code.request_suppressed";
    public const string EmailCodeRequestRateLimited = "ashlar.email_code.request_rate_limited";
    public const string EmailCodeVerificationRateLimited = "ashlar.email_code.verification_rate_limited";
    public const string MagicLinkRequested = "ashlar.magic_link.requested";
    public const string MagicLinkRequestSuppressed = "ashlar.magic_link.request_suppressed";
    public const string MagicLinkRequestRateLimited = "ashlar.magic_link.request_rate_limited";
    public const string MagicLinkVerificationRateLimited = "ashlar.magic_link.verification_rate_limited";
    public const string RecoveryCodesGenerated = "ashlar.recovery_codes.generated";
    public const string RecoveryCodesRevoked = "ashlar.recovery_codes.revoked";
    public const string RecoveryCodeVerificationRateLimited = "ashlar.recovery_codes.verification_rate_limited";
    public const string SessionCreated = "ashlar.session.created";
    public const string SessionValidated = "ashlar.session.validated";
    public const string SessionValidationFailed = "ashlar.session.validation_failed";
    public const string SessionExpired = "ashlar.session.expired";
    public const string SessionRevoked = "ashlar.session.revoked";
    public const string SessionsRevokedForUser = "ashlar.session.revoked_for_user";
    public const string InvitationCreated = "ashlar.invitation.created";
    public const string InvitationAccepted = "ashlar.invitation.accepted";
    public const string InvitationRevoked = "ashlar.invitation.revoked";
    public const string InvitationRateLimited = "ashlar.invitation.rate_limited";
    public const string AuthenticationHandshakeCreated = "ashlar.authentication.handshake.created";
    public const string AuthenticationHandshakeFactorVerified = "ashlar.authentication.handshake.factor_verified";
    public const string AuthenticationHandshakeCompleted = "ashlar.authentication.handshake.completed";
    public const string AuthenticationHandshakeRevoked = "ashlar.authentication.handshake.revoked";
    public const string AuthenticationHandshakeExpired = "ashlar.authentication.handshake.expired";
    public const string AuthenticationHandshakeFailed = "ashlar.authentication.handshake.failed";
    public const string AuthenticationHandshakeVerificationRateLimited = "ashlar.authentication.handshake.verification_rate_limited";
    public const string AuthorizationGrantCreated = "ashlar.authorization.grant.created";
    public const string AuthorizationGrantRevoked = "ashlar.authorization.grant.revoked";
    public const string TotpEnrollmentStarted = "ashlar.totp.enrollment_started";
    public const string TotpEnrollmentCompleted = "ashlar.totp.enrollment_completed";
    public const string TotpDisabled = "ashlar.totp.disabled";
    public const string TotpVerificationRateLimited = "ashlar.totp.verification_rate_limited";
    public const string BootstrapInvitationCreated = "ashlar.bootstrap.invitation.created";
    public const string BootstrapCompleted = "ashlar.bootstrap.completed";
    public const string EmailVerificationRequested = "ashlar.email_verification.requested";
    public const string EmailVerified = "ashlar.email_verification.verified";
    public const string EmailVerificationFailed = "ashlar.email_verification.failed";
    public const string EmailVerificationRateLimited = "ashlar.email_verification.rate_limited";
    public const string EmailVerificationVerificationRateLimited = "ashlar.email_verification.verification_rate_limited";
    public const string EmailChangeRequested = "ashlar.email_change.requested";
    public const string EmailChangeRequestSuppressed = "ashlar.email_change.request_suppressed";
    public const string EmailChanged = "ashlar.email_change.changed";
    public const string EmailChangeFailed = "ashlar.email_change.failed";
    public const string EmailChangeRateLimited = "ashlar.email_change.rate_limited";
    public const string EmailChangeVerificationRateLimited = "ashlar.email_change.verification_rate_limited";
}
