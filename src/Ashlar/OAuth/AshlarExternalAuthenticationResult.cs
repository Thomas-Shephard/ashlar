namespace Ashlar.OAuth;

/// <summary>
/// Describes the result of authenticating a validated external callback.
/// </summary>
/// <param name="Status">The external completion status.</param>
/// <param name="Authentication">The MFA-aware authentication result when the ticket was mapped.</param>
public sealed record AshlarExternalAuthenticationResult(
    AshlarExternalAuthenticationStatus Status,
    MfaAuthenticationResult? Authentication = null)
{
    /// <summary>
    /// Gets a value indicating whether the external ticket was accepted.
    /// </summary>
    public bool Succeeded => Status == AshlarExternalAuthenticationStatus.Succeeded;
}

/// <summary>
/// Defines external authentication completion states.
/// </summary>
public enum AshlarExternalAuthenticationStatus
{
    /// <summary>
    /// The external authentication status is unknown.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Primary external authentication succeeded or requires MFA completion.
    /// </summary>
    Succeeded = 1,

    /// <summary>
    /// The external callback did not authenticate successfully.
    /// </summary>
    AuthenticationFailed = 2,

    /// <summary>
    /// The requested external provider is not configured.
    /// </summary>
    UnsupportedProvider = 3,

    /// <summary>
    /// The external principal was missing required data.
    /// </summary>
    InvalidPrincipal = 4,

    /// <summary>
    /// The external ticket was issued by a different configured provider.
    /// </summary>
    ProviderMismatch = 5,

    /// <summary>
    /// The external authentication attempt was blocked by rate limiting.
    /// </summary>
    RateLimited = 6
}
