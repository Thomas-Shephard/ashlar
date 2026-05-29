using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Applies layered provider-neutral limits to secondary factor verification attempts.
/// </summary>
/// <param name="rateLimiter">The underlying authentication rate limiter.</param>
/// <param name="options">Secondary factor rate-limit options.</param>
public sealed class AuthenticationFactorRateLimiter(
    IAuthenticationRateLimiter rateLimiter,
    IOptions<AuthenticationFactorRateLimitOptions>? options = null) : IAuthenticationFactorRateLimiter
{
    private readonly IAuthenticationRateLimiter _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    private readonly AuthenticationFactorRateLimitOptions _options = ValidateOptions(options?.Value ?? new AuthenticationFactorRateLimitOptions());

    /// <inheritdoc />
    public async Task<RateLimitDecision> CheckAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!_options.Enabled || _options.ExcludedProviders.Contains(AuthenticationFactorRateLimitKeyBuilder.NormalizeProviderSelector(providerKey)))
        {
            return RateLimitDecision.Allow();
        }

        var rule = ResolveRule(providerKey);
        foreach (var attempt in AuthenticationFactorRateLimitKeyBuilder.BuildAttempts(context, providerKey))
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
        return _options.ProviderRules.TryGetValue(AuthenticationFactorRateLimitKeyBuilder.NormalizeProviderSelector(providerKey), out var rule)
            ? rule
            : _options.DefaultRule;
    }

    private static AuthenticationFactorRateLimitOptions ValidateOptions(AuthenticationFactorRateLimitOptions options)
    {
        if (!AuthenticationFactorRateLimitOptions.Validate(options))
        {
            throw new OptionsValidationException(
                nameof(AuthenticationFactorRateLimitOptions),
                typeof(AuthenticationFactorRateLimitOptions),
                ["Secondary factor rate-limit options are invalid."]);
        }

        return options;
    }
}
