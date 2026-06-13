namespace Ashlar.Auditing;

/// <summary>
/// Defines provider-neutral failure reason values for security events.
/// </summary>
public static class SecurityEventFailureReasons
{
    /// <summary>
    /// The submitted assertion did not match a registered provider.
    /// </summary>
    public const string ProviderUnsupported = "provider_unsupported";
    /// <summary>
    /// Credential verification failed.
    /// </summary>
    public const string InvalidCredentials = "invalid_credentials";
    /// <summary>
    /// The user account is disabled.
    /// </summary>
    public const string UserDisabled = "user_disabled";
    /// <summary>
    /// The user account is locked.
    /// </summary>
    public const string UserLocked = "user_locked";
    /// <summary>
    /// The user account is suspended.
    /// </summary>
    public const string UserSuspended = "user_suspended";
    /// <summary>
    /// Automatic account lockout blocked the attempt.
    /// </summary>
    public const string AutomaticAccountLockout = "automatic_account_lockout";
    /// <summary>
    /// A post-authentication credential lifecycle update failed.
    /// </summary>
    public const string CredentialUpdateFailed = "credential_update_failed";
    /// <summary>
    /// Protected credential or token payload unprotect failed.
    /// </summary>
    public const string UnprotectFailed = "unprotect_failed";
    /// <summary>
    /// Bootstrap setup authorization was not supplied.
    /// </summary>
    public const string BootstrapSetupAuthorizationMissing = "bootstrap_setup_authorization_missing";
    /// <summary>
    /// Bootstrap setup authorization was supplied but invalid.
    /// </summary>
    public const string BootstrapSetupAuthorizationInvalid = "bootstrap_setup_authorization_invalid";
    /// <summary>
    /// A rate limit blocked the operation.
    /// </summary>
    public const string RateLimited = "rate_limited";
    /// <summary>
    /// The submitted session could not be validated.
    /// </summary>
    public const string SessionValidationFailed = "session_validation_failed";
    /// <summary>
    /// Session validation failed because the session expired.
    /// </summary>
    public const string SessionExpired = "session_expired";
    /// <summary>
    /// Session validation failed because the session was revoked.
    /// </summary>
    public const string SessionRevoked = "session_revoked";
}
