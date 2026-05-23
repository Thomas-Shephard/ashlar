namespace Ashlar.OAuth;

/// <summary>
/// Describes the result of authenticating a validated external OIDC credential with Ashlar.
/// </summary>
/// <param name="Status">The external credential verification status.</param>
/// <param name="Authentication">The Ashlar response when credential verification was attempted.</param>
/// <param name="Assertion">The mapped external identity assertion when available.</param>
public sealed record AshlarExternalCredentialAuthenticationResult(
    AshlarExternalCredentialAuthenticationStatus Status,
    AuthenticationResponse? Authentication = null,
    ExternalIdentityAssertion? Assertion = null)
{
    /// <summary>
    /// Gets a value indicating whether the external credential authenticated successfully with Ashlar.
    /// </summary>
    public bool Succeeded => Status == AshlarExternalCredentialAuthenticationStatus.Succeeded;
}

/// <summary>
/// Defines external credential authentication states.
/// </summary>
public enum AshlarExternalCredentialAuthenticationStatus
{
    /// <summary>
    /// The external credential authentication result has not been set.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The external credential authenticated successfully with Ashlar.
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
    /// Ashlar requires MFA before the application may issue a session.
    /// </summary>
    MfaRequired = 8
}
