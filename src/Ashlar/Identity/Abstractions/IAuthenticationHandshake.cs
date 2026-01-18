using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Represents the state of an ongoing authentication process, particularly for multifactor authentication.
/// </summary>
public interface IAuthenticationHandshake
{
    /// <summary>
    /// Gets the ID of the user being authenticated.
    /// </summary>
    Guid UserId { get; }

    /// <summary>
    /// Gets the list of factor types that have already been verified.
    /// </summary>
    IReadOnlyList<ProviderType> VerifiedFactors { get; }

    /// <summary>
    /// Gets the tenant context for the authentication.
    /// </summary>
    Guid? TenantId { get; }

    /// <summary>
    /// Gets the original session ticket that was used to create this handshake, if any.
    /// </summary>
    string? SessionTicket { get; }
}
