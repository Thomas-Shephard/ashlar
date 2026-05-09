namespace Ashlar.Identity.Models;

/// <summary>
/// Request parameters for revoking a specific authentication session.
/// </summary>
public sealed record RevokeAuthenticationSessionRequest
{
    /// <summary>
    /// The unique identifier of the session to revoke.
    /// </summary>
    public required Guid SessionId { get; init; }

    /// <summary>
    /// An optional reason for revocation.
    /// </summary>
    public string? Reason { get; init; }
}
