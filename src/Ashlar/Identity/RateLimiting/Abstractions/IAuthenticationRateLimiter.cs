using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// A framework-neutral rate limiter for securing authentication-related flows.
/// </summary>
public interface IAuthenticationRateLimiter
{
    /// <summary>
    /// Checks whether the given attempt is allowed under the specified rule.
    /// If the attempt is allowed, one permit is consumed.
    /// </summary>
    /// <param name="attempt">Details about the attempt being made.</param>
    /// <param name="rule">The rate limit rule to enforce.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A decision indicating whether the attempt is allowed or blocked.</returns>
    Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default);
}
