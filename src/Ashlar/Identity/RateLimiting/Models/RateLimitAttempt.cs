namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Provider-neutral metadata for one rate-limited authentication attempt.
/// </summary>
public sealed class RateLimitAttempt
{
    /// <summary>
    /// Hashed persistence key identifying the limited bucket.
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// Authentication flow or operation being limited.
    /// </summary>
    public string? Purpose { get; init; }

    /// <summary>
    /// Client IP address associated with the attempt, when available. Treat as personal data.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// User identifier associated with the attempt, when known.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// Normalized email associated with the attempt, when relevant.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Host-defined request or trace correlation identifier, when available.
    /// </summary>
    public string? CorrelationId { get; init; }
}
