namespace Ashlar.Auditing;

/// <summary>
/// Stable event type names emitted by Ashlar security flows.
/// </summary>
public static class AshlarSecurityEventTypes
{
    public const string AuthenticationSucceeded = "ashlar.authentication.succeeded";
    public const string AuthenticationFailed = "ashlar.authentication.failed";
    public const string CredentialLinked = "ashlar.credential.linked";
    public const string CredentialConsumed = "ashlar.credential.consumed";
    public const string CredentialUpdatePersisted = "ashlar.credential.update_persisted";
    public const string CredentialUpdateFailed = "ashlar.credential.update_failed";
    public const string SessionCreated = "ashlar.session.created";
    public const string SessionValidated = "ashlar.session.validated";
    public const string SessionValidationFailed = "ashlar.session.validation_failed";
    public const string SessionExpired = "ashlar.session.expired";
    public const string SessionRevoked = "ashlar.session.revoked";
    public const string SessionsRevokedForUser = "ashlar.session.revoked_for_user";
}
