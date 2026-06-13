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
    /// <param name="attempt">Safe, normalized bucket metadata for the authentication attempt.</param>
    /// <param name="rule">Rate-limit rule to enforce for the bucket.</param>
    /// <param name="cancellationToken">Token for aborting rate-limit storage work.</param>
    /// <returns>Decision indicating whether the attempt is allowed, blocked, or delayed.</returns>
    Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default);
}
