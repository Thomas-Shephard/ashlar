using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Applies provider-neutral rate limits to primary authentication attempts.
/// </summary>
public interface IPrimaryAuthenticationRateLimiter
{
    /// <summary>
    /// Checks whether a primary authentication attempt is permitted.
    /// </summary>
    /// <param name="context">Authentication request context used to derive rate-limit buckets.</param>
    /// <param name="assertion">Provider-supplied credential assertion used to derive identity buckets.</param>
    /// <param name="providerKey">The resolved or requested provider identity.</param>
    /// <param name="cancellationToken">A token that can cancel primary authentication rate-limit checks.</param>
    /// <returns>Decision indicating whether primary authentication may continue.</returns>
    Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default);
}
