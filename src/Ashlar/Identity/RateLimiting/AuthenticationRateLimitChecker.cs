using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Centralizes authentication rate-limit rule validation and key construction.
/// </summary>
/// <param name="rateLimiter">The underlying authentication rate limiter.</param>
/// <remarks>
/// Initializes a configured authentication rate-limit checker.
/// </remarks>
public sealed class AuthenticationRateLimitChecker(IAuthenticationRateLimiter rateLimiter)
{
    private readonly IAuthenticationRateLimiter _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));

    /// <summary>
    /// Checks a single authentication rate-limit bucket.
    /// </summary>
    /// <param name="check">The bucket check.</param>
    /// <param name="cancellationToken">A token that can cancel the rate-limit check.</param>
    /// <returns>The rate-limit decision.</returns>
    public Task<RateLimitDecision> CheckAsync(
        AuthenticationRateLimitCheck check,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(check);

        if (!AuthenticationRateLimitRuleValidator.IsValid(check.Rule))
        {
            throw new ArgumentException("Rate-limit rule is invalid.", nameof(check));
        }

        return _rateLimiter.CheckAsync(AuthenticationRateLimitKeyBuilder.BuildAttempt(check), check.Rule, cancellationToken);
    }
}
