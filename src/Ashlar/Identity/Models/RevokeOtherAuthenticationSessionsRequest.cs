namespace Ashlar.Identity.Models;

/// <summary>
/// Request parameters for revoking all sessions for a user except one.
/// </summary>
public sealed record RevokeOtherAuthenticationSessionsRequest
{
    /// <summary>
    /// The session ID that should NOT be revoked.
    /// </summary>
    public required Guid CurrentSessionId { get; init; }

    /// <summary>
    /// An optional reason for revocation.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// The IP address of the client requesting revocation.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// The user agent of the client requesting revocation.
    /// </summary>
    public string? UserAgent { get; init; }
}
