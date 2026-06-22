namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// The result of evaluating a rate limit attempt.
/// </summary>
public sealed class RateLimitDecision
{
    /// <summary>
    /// Creates an allowed decision for disabled or excluded rate-limit scopes.
    /// </summary>
    /// <returns>An allowed rate-limit decision.</returns>
    public static RateLimitDecision Allow()
    {
        return new RateLimitDecision
        {
            Status = RateLimitStatus.Allowed,
            Remaining = int.MaxValue,
            WindowResetAt = DateTimeOffset.MaxValue
        };
    }

    /// <summary>
    /// Gets the decision produced for the attempted authentication operation.
    /// </summary>
    /// <remarks>
    /// <see cref="RateLimitStatus.Allowed"/> can represent a consumed permit, a disabled limiter, an excluded scope,
    /// or another scope that was not subject to enforcement. Only <see cref="RateLimitStatus.Blocked"/> is a hard stop.
    /// </remarks>
    public required RateLimitStatus Status { get; init; }

    /// <summary>
    /// Gets a value indicating whether the caller may continue the authentication operation.
    /// </summary>
    public bool IsAllowed => Status == RateLimitStatus.Allowed;

    /// <summary>
    /// Gets the earliest retry instant when the attempt is blocked.
    /// </summary>
    public DateTimeOffset? RetryAfter { get; init; }

    /// <summary>
    /// Gets the number of remaining permits in the current rate-limit window.
    /// </summary>
    public required int Remaining { get; init; }

    /// <summary>
    /// Gets the instant when the current rate-limit window resets.
    /// </summary>
    public required DateTimeOffset WindowResetAt { get; init; }
}
