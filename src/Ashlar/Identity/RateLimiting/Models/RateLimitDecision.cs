namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// The result of evaluating a rate limit attempt.
/// </summary>
public sealed class RateLimitDecision
{
    /// <summary>
    /// The status of the attempt.
    /// </summary>
    public required RateLimitStatus Status { get; init; }

    /// <summary>
    /// True if the attempt is allowed; otherwise, false.
    /// </summary>
    public bool IsAllowed => Status == RateLimitStatus.Allowed;

    /// <summary>
    /// If the attempt is blocked, indicates when the caller may try again.
    /// </summary>
    public DateTimeOffset? RetryAfter { get; init; }

    /// <summary>
    /// The number of remaining permits in the current window.
    /// </summary>
    public required int Remaining { get; init; }

    /// <summary>
    /// The time when the current rate limit window will reset.
    /// </summary>
    public required DateTimeOffset WindowResetAt { get; init; }
}
