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
    /// <param name="attempt">The attempt value.</param>
    /// <param name="rule">The rule value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default);
}


