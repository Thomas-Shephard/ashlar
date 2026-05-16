namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Defines the rule for how a rate limit is enforced.
/// </summary>
public sealed class RateLimitRule
{
    /// <summary>
    /// The maximum number of permitted attempts within the <see cref="Window"/>.
    /// </summary>
    public required int PermitLimit { get; init; }

    /// <summary>
    /// The time window for evaluating the permit limit.
    /// </summary>
    public required TimeSpan Window { get; init; }

    /// <summary>
    /// An optional duration to block further attempts once the permit limit has been exceeded.
    /// If <see langword="null" />, the caller is only blocked until the current window expires.
    /// </summary>
    public TimeSpan? BlockDuration { get; init; }
}
