namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// A summary of an authentication session for user-facing device/session management.
/// </summary>
public sealed record AuthenticationSessionSummary
{
    /// <summary>
    /// Stable identifier used by session management APIs.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// UTC time when the session was issued.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// UTC time after which the session is no longer accepted.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// UTC time when validation last observed this session.
    /// </summary>
    public DateTimeOffset? LastSeenAt { get; init; }

    /// <summary>
    /// UTC time when the session was revoked, if applicable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// The provider-neutral, display-safe reason for revocation, if applicable.
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
    /// Provider-neutral session metadata safe for display; should not contain secrets or raw tokens.
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
