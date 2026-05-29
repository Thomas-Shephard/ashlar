using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Applies layered provider-neutral limits to primary authentication attempts.
/// </summary>
/// <param name="rateLimiter">The underlying authentication rate limiter.</param>
/// <param name="options">Primary authentication rate-limit options.</param>
/// <remarks>
/// Initializes a configured primary authentication rate limiter.
/// </remarks>
public sealed class PrimaryAuthenticationRateLimiter(
    IAuthenticationRateLimiter rateLimiter,
    IOptions<PrimaryAuthenticationRateLimitOptions>? options = null) : IPrimaryAuthenticationRateLimiter
{
    private readonly IAuthenticationRateLimiter _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    private readonly PrimaryAuthenticationRateLimitOptions _options = ValidateOptions(options?.Value ?? new PrimaryAuthenticationRateLimitOptions());

    /// <inheritdoc />
    public async Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_options.Enabled || _options.ExcludedProviders.Contains(PrimaryAuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(providerKey)))
        {
            return RateLimitDecision.Allow();
        }

        var rule = ResolveRule(providerKey);
        foreach (var attempt in PrimaryAuthenticationRateLimitKeyBuilder.BuildAttempts(context, assertion, providerKey))
        {
            var decision = await _rateLimiter.CheckAsync(attempt, rule, cancellationToken);
            if (!decision.IsAllowed)
            {
                return decision;
            }
        }

        return RateLimitDecision.Allow();
    }

    private RateLimitRule ResolveRule(AuthenticationProviderKey providerKey)
    {
        return _options.ProviderRules.TryGetValue(PrimaryAuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(providerKey), out var rule)
            ? rule
            : _options.DefaultRule;
    }

    private static PrimaryAuthenticationRateLimitOptions ValidateOptions(PrimaryAuthenticationRateLimitOptions options)
    {
        if (!PrimaryAuthenticationRateLimitOptions.Validate(options))
        {
            throw new OptionsValidationException(
                nameof(PrimaryAuthenticationRateLimitOptions),
                typeof(PrimaryAuthenticationRateLimitOptions),
                ["Primary authentication rate-limit options are invalid."]);
        }

        return options;
    }
}
