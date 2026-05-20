namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Represents the persisted state for a single rate limit key and purpose.
/// </summary>
public sealed class RateLimitState
{
    /// <summary>
    /// The number of attempts consumed in the current window.
    /// </summary>
    public int Count { get; set; }

    /// <summary>
    /// The start time of the current rate limit window.
    /// </summary>
    public DateTimeOffset WindowStart { get; set; }

    /// <summary>
    /// The time until which attempts are blocked, if the limit has been exceeded.
    /// </summary>
    public DateTimeOffset? BlockedUntil { get; set; }
}


