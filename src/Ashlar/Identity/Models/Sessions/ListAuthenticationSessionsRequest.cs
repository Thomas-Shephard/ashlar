namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for listing authentication sessions.
/// </summary>
public sealed record ListAuthenticationSessionsRequest
{
    /// <summary>
    /// Whether to only include active (not expired and not revoked) sessions.
    /// </summary>
    public bool ActiveOnly { get; init; } = true;

    /// <summary>
    /// The session ID that should be marked as "current" in the results.
    /// </summary>
    public Guid? CurrentSessionId { get; init; }
}





