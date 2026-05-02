namespace Ashlar.Auditing;

internal static class SecurityEventFailureReasons
{
    public const string ProviderUnsupported = "provider_unsupported";
    public const string InvalidCredentials = "invalid_credentials";
    public const string UserDisabled = "user_disabled";
    public const string CredentialUpdateFailed = "credential_update_failed";
    public const string SessionValidationFailed = "session_validation_failed";
    public const string SessionExpired = "session_expired";
    public const string SessionRevoked = "session_revoked";
}
