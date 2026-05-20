namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Represents an attempt to perform an action that may be rate limited.
/// </summary>
public sealed class RateLimitAttempt
{
    /// <summary>
    /// The primary key identifying the resource being limited (e.g., "email:test@example.com").
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// An optional identifier for the purpose or flow of the attempt (e.g., "PasswordlessEmail", "MfaChallenge").
    /// </summary>
    public string? Purpose { get; init; }

    /// <summary>
    /// The IP address of the client making the attempt, if available and relevant.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// The user ID associated with the attempt, if known.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// The email address associated with the attempt, if relevant.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// A correlation ID for tracking the attempt across logs or audit events.
    /// </summary>
    public string? CorrelationId { get; init; }
}


