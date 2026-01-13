namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Represents a stateful authentication handshake, tracking progress across multiple factors.
/// </summary>
public interface IAuthenticationHandshake
{
    /// <summary>
    /// A secure, encrypted ticket representing the current state of the handshake.
    /// </summary>
    string SessionTicket { get; }

    /// <summary>
    /// The ID of the user being authenticated.
    /// </summary>
    Guid UserId { get; }

    /// <summary>
    /// The list of factors that have already been successfully verified.
    /// </summary>
    IReadOnlyList<string> VerifiedFactors { get; }

    /// <summary>
    /// The tenant ID associated with the authentication attempt, if any.
    /// </summary>
    Guid? TenantId { get; }
}
