using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Support;

internal sealed class AllowPrimaryAuthenticationRateLimiter : IPrimaryAuthenticationRateLimiter
{
    public static AllowPrimaryAuthenticationRateLimiter Instance { get; } = new();

    private AllowPrimaryAuthenticationRateLimiter()
    {
    }

    public Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(RateLimitDecision.Allow());
    }
}
