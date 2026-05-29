using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Applies provider-neutral rate limits to secondary factor verification attempts.
/// </summary>
public interface IAuthenticationFactorRateLimiter
{
    /// <summary>
    /// Checks whether the secondary factor verification attempt is allowed.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="providerKey">The secondary factor provider identity.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The rate-limit decision.</returns>
    Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default);
}
