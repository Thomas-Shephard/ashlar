namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Shared settings for provider-neutral authentication rate limiting.
/// </summary>
public abstract class AuthenticationRateLimitOptions
{
    /// <summary>
    /// Whether this authentication throttle is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Allows authentication to proceed when the configured rate-limit backend throws.
    /// Enable this only for deployments that knowingly prefer availability over brute-force protection while the relevant authentication rate limiter is unavailable.
    /// </summary>
    public bool FailOpenOnBackendFailure { get; set; }

    /// <summary>
    /// Default rule applied when no provider-specific override matches.
    /// </summary>
    public abstract RateLimitRule DefaultRule { get; set; }

    /// <summary>
    /// Gets provider-specific rules keyed as provider type/name, for example <c>local:local</c>.
    /// </summary>
    public IDictionary<string, RateLimitRule> ProviderRules { get; } = new Dictionary<string, RateLimitRule>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets providers deliberately excluded from this authentication throttle.
    /// </summary>
    public ISet<string> ExcludedProviders { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Validates shared authentication rate-limit settings.
    /// </summary>
    /// <param name="options">Authentication rate-limit settings to validate.</param>
    /// <returns><see langword="true" /> when the shared rule and provider settings are valid.</returns>
    protected static bool ValidateCore(AuthenticationRateLimitOptions? options)
    {
        return options != null
            && AuthenticationRateLimitRuleValidator.IsValid(options.DefaultRule)
            && options.ProviderRules.All(rule => PrimaryAuthenticationRateLimitOptions.IsProviderSelectorValid(rule.Key) && AuthenticationRateLimitRuleValidator.IsValid(rule.Value))
            && options.ExcludedProviders.All(PrimaryAuthenticationRateLimitOptions.IsProviderSelectorValid);
    }
}
