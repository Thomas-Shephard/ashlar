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
    public const string SessionCreated = "ashlar.session.created";
    public const string SessionValidated = "ashlar.session.validated";
    public const string SessionValidationFailed = "ashlar.session.validation_failed";
    public const string SessionExpired = "ashlar.session.expired";
    public const string SessionRevoked = "ashlar.session.revoked";
    public const string SessionsRevokedForUser = "ashlar.session.revoked_for_user";
}
