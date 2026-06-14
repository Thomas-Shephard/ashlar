namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Configures provider-neutral secondary factor verification rate limiting.
/// </summary>
public sealed class AuthenticationFactorRateLimitOptions
{
    /// <summary>
    /// Whether secondary factor rate limiting is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Allows MFA factor verification to proceed when secondary-factor throttling storage throws.
    /// Enable this only for deployments that knowingly prefer MFA availability over brute-force protection while the factor-verification rate limiter is unavailable.
    /// </summary>
    public bool FailOpenOnBackendFailure { get; set; }

    /// <summary>
    /// Default rule applied to secondary factor verification attempts.
    /// </summary>
    public RateLimitRule DefaultRule { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(5),
        BlockDuration = TimeSpan.FromMinutes(5)
    };

    /// <summary>
    /// Gets provider-specific rules keyed as provider type/name, for example <c>passkey:passkey</c>.
    /// </summary>
    public IDictionary<string, RateLimitRule> ProviderRules { get; } = new Dictionary<string, RateLimitRule>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets providers deliberately excluded from provider-neutral factor rate limiting.
    /// </summary>
    public ISet<string> ExcludedProviders { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Validates secondary factor rate-limit options.
    /// </summary>
    /// <param name="options">Secondary factor rate-limit settings to validate.</param>
    /// <returns><see langword="true" /> when factor verification attempts can use the supplied settings.</returns>
    public static bool Validate(AuthenticationFactorRateLimitOptions? options)
    {
        if (options == null || !AuthenticationRateLimitRuleValidator.IsValid(options.DefaultRule))
        {
            return false;
        }

        return options.ProviderRules.All(rule => PrimaryAuthenticationRateLimitOptions.IsProviderSelectorValid(rule.Key) && AuthenticationRateLimitRuleValidator.IsValid(rule.Value))
            && options.ExcludedProviders.All(PrimaryAuthenticationRateLimitOptions.IsProviderSelectorValid);
    }
}
