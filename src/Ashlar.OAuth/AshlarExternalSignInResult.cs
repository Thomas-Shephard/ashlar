namespace Ashlar.OAuth;

/// <summary>
/// Describes the result of completing an external sign-in callback.
/// </summary>
/// <param name="Status">The external sign-in status.</param>
/// <param name="Authentication">The Ashlar authentication response when authentication was attempted.</param>
/// <param name="Assertion">The mapped external identity assertion when available.</param>
public sealed record AshlarExternalSignInResult(
    AshlarExternalSignInStatus Status,
    AuthenticationResponse? Authentication = null,
    ExternalIdentityAssertion? Assertion = null)
{
    /// <summary>
    /// Gets a value indicating whether external sign-in completed successfully.
    /// </summary>
    public bool Succeeded => Status == AshlarExternalSignInStatus.Succeeded;
}

/// <summary>
/// Defines external sign-in completion states.
/// </summary>
public enum AshlarExternalSignInStatus
{
    /// <summary>
    /// The external sign-in completed successfully.
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
    /// Ashlar authentication failed, commonly because the external credential is not linked.
    /// </summary>
    AshlarAuthenticationFailed = 5,
    /// <summary>
    /// The external ticket was issued by a different configured provider.
    /// </summary>
    ProviderMismatch = 6,
    /// <summary>
    /// The Ashlar user is disabled.
    /// </summary>
    Disabled = 7,
    /// <summary>
    /// Ashlar requires MFA before completing sign-in.
    /// </summary>
    MfaRequired = 8
}
