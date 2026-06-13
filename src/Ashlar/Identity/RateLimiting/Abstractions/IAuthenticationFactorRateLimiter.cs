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
    /// <param name="context">Authentication request context used to derive source and user buckets.</param>
    /// <param name="providerKey">The secondary factor provider identity.</param>
    /// <param name="cancellationToken">Token for aborting rate-limit storage work.</param>
    /// <returns>Decision indicating whether the factor verification attempt may continue.</returns>
    Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default);
}
