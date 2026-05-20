namespace Ashlar.Auditing;

/// <summary>
/// Provides security event failure reasons behavior.
/// </summary>
public static class SecurityEventFailureReasons
{
    /// <summary>
    /// Defines the provider unsupported value.
    /// </summary>
    public const string ProviderUnsupported = "provider_unsupported";
    /// <summary>
    /// Defines the invalid credentials value.
    /// </summary>
    public const string InvalidCredentials = "invalid_credentials";
    /// <summary>
    /// Defines the user disabled value.
    /// </summary>
    public const string UserDisabled = "user_disabled";
    /// <summary>
    /// Defines the credential update failed value.
    /// </summary>
    public const string CredentialUpdateFailed = "credential_update_failed";
    /// <summary>
    /// Defines the unprotect failed value.
    /// </summary>
    public const string UnprotectFailed = "unprotect_failed";
    /// <summary>
    /// Defines the session validation failed value.
    /// </summary>
    public const string SessionValidationFailed = "session_validation_failed";
    /// <summary>
    /// Defines the session expired value.
    /// </summary>
    public const string SessionExpired = "session_expired";
    /// <summary>
    /// Defines the session revoked value.
    /// </summary>
    public const string SessionRevoked = "session_revoked";
}


