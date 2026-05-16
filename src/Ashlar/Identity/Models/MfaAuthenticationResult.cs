using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models;

/// <summary>
/// Defines the available mfa authentication status values.
/// </summary>
public enum MfaAuthenticationStatus
{
    /// <summary>
    /// Represents the failed value.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Represents the succeeded value.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Represents the mfa required value.
    /// </summary>
    MfaRequired = 2,
    /// <summary>
    /// Represents the handshake incomplete value.
    /// </summary>
    HandshakeIncomplete = 3
}

/// <summary>
/// Represents the mfa authentication result data model.
/// </summary>
/// <param name="Status">The status value.</param>
/// <param name="User">The user value.</param>
/// <param name="HandshakeToken">The handshake token value.</param>
/// <param name="RequiredFactors">The required factors value.</param>
/// <param name="Claims">The claims value.</param>
/// <param name="ErrorMessage">The error message value.</param>
public sealed record MfaAuthenticationResult(
    MfaAuthenticationStatus Status,
    IUser? User = null,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    IDictionary<string, string>? Claims = null,
    string? ErrorMessage = null);
