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
    /// <param name="context">The authentication context.</param>
    /// <param name="assertion">The assertion being authenticated.</param>
    /// <param name="providerKey">The resolved or requested provider identity.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The rate-limit decision.</returns>
    Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default);
}
