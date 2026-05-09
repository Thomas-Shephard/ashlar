namespace Ashlar.Identity.Models;

/// <summary>
/// A summary of an authentication session for user-facing device/session management.
/// </summary>
public sealed record AuthenticationSessionSummary
{
    /// <summary>
    /// The unique identifier for the session.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// When the session was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// When the session expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// When the session was last observed.
    /// </summary>
    public DateTimeOffset? LastSeenAt { get; init; }

    /// <summary>
    /// When the session was revoked, if applicable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// The reason for revocation, if applicable.
    /// </summary>
    public string? RevocationReason { get; init; }

    /// <summary>
    /// The IP address associated with the session, if stored and permitted by configuration.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// The user agent associated with the session, if stored and permitted by configuration.
    /// </summary>
    public string? UserAgent { get; init; }

    /// <summary>
    /// Optional metadata associated with the session.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Whether this session is the one making the current request.
    /// </summary>
    public bool IsCurrent { get; init; }

    /// <summary>
    /// Whether the session is currently active (not expired and not revoked).
    /// </summary>
    public bool IsActive { get; init; }
}
