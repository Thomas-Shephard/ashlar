namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Defines the available mfa authentication status values.
/// </summary>
public enum MfaAuthenticationStatus
{
    /// <summary>
    /// Authentication failed.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Authentication completed successfully.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Additional MFA factors are required.
    /// </summary>
    MfaRequired = 2,
    /// <summary>
    /// The MFA handshake exists but not all required factors have been verified.
    /// </summary>
    HandshakeIncomplete = 3,
    /// <summary>
    /// Authentication was blocked by a rate limiter.
    /// </summary>
    RateLimited = 4
}

/// <summary>
/// Result returned by MFA-aware authentication flows.
/// </summary>
/// <param name="Status">The authentication outcome.</param>
/// <param name="User">The authenticated user when authentication succeeds.</param>
/// <param name="HandshakeToken">The raw handshake token when more MFA factors are required.</param>
/// <param name="RequiredFactors">The MFA factors still required for the handshake.</param>
/// <param name="Claims">Additional claims produced by the authentication provider.</param>
/// <param name="ErrorMessage">A display-safe error message when authentication fails.</param>
public sealed record MfaAuthenticationResult(
    MfaAuthenticationStatus Status,
    IUser? User = null,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
    string? ErrorMessage = null)
{
    /// <summary>
    /// Initializes a new instance of the MFA authentication result class from single-value claims.
    /// </summary>
    /// <param name="status">The authentication outcome.</param>
    /// <param name="user">The authenticated user when authentication succeeds.</param>
    /// <param name="handshakeToken">The raw handshake token when more MFA factors are required.</param>
    /// <param name="requiredFactors">The MFA factors still required for the handshake.</param>
    /// <param name="claims">Additional single-value claims produced by the authentication provider.</param>
    /// <param name="errorMessage">A display-safe error message when authentication fails.</param>
    public MfaAuthenticationResult(
        MfaAuthenticationStatus status,
        IUser? user,
        string? handshakeToken,
        IEnumerable<string>? requiredFactors,
        IDictionary<string, string>? claims,
        string? errorMessage = null)
        : this(status, user, handshakeToken, requiredFactors, AuthenticationClaims.FromSingleValues(claims), errorMessage)
    {
    }
}
