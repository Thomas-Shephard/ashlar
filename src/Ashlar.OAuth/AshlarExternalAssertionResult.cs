namespace Ashlar.OAuth;

/// <summary>
/// Describes the result of completing an external callback into a mapped Ashlar external identity without authenticating it.
/// </summary>
/// <param name="Status">The external completion status.</param>
/// <param name="Assertion">The mapped external identity when available.</param>
public sealed record AshlarExternalAssertionResult(
    AshlarExternalAssertionStatus Status,
    ExternalIdentityAssertion? Assertion = null)
{
    /// <summary>
    /// Gets a value indicating whether the external assertion was mapped successfully.
    /// </summary>
    public bool Succeeded => Status == AshlarExternalAssertionStatus.Succeeded;
}

/// <summary>
/// Defines external assertion completion states.
/// </summary>
public enum AshlarExternalAssertionStatus
{
    /// <summary>
    /// The external assertion status is unknown.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The external callback was mapped successfully.
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
    ProviderMismatch = 6
}
