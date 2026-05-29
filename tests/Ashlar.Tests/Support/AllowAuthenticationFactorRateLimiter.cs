using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Support;

internal sealed class AllowAuthenticationFactorRateLimiter : IAuthenticationFactorRateLimiter
{
    public static readonly AllowAuthenticationFactorRateLimiter Instance = new();

    private AllowAuthenticationFactorRateLimiter()
    {
    }

    public Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(RateLimitDecision.Allow());
    }
}
