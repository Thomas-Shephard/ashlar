namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Configures provider-neutral primary authentication rate limiting.
/// </summary>
public sealed class PrimaryAuthenticationRateLimitOptions
{
    /// <summary>
    /// Whether primary authentication rate limiting is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Allows primary authentication to continue when the configured rate-limit backend throws.
    /// Keep this disabled unless the deployment knowingly prefers sign-in availability over brute-force protection during rate-limit backend outages.
    /// </summary>
    public bool FailOpenOnBackendFailure { get; set; }

    /// <summary>
    /// Default rule applied to primary authentication attempts.
    /// </summary>
    public RateLimitRule DefaultRule { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(10),
        BlockDuration = TimeSpan.FromMinutes(10)
    };

    /// <summary>
    /// Gets provider-specific rules keyed as provider type/name, for example <c>local:local</c>.
    /// </summary>
    public IDictionary<string, RateLimitRule> ProviderRules { get; } = new Dictionary<string, RateLimitRule>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets providers deliberately excluded from primary authentication rate limiting.
    /// Entries are keyed as provider type/name, for example <c>oidc:contoso</c>.
    /// </summary>
    public ISet<string> ExcludedProviders { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Validates primary authentication rate-limit options.
    /// </summary>
    /// <param name="options">Primary authentication rate-limit settings to validate.</param>
    /// <returns><see langword="true" /> when primary authentication attempts can use the supplied settings.</returns>
    public static bool Validate(PrimaryAuthenticationRateLimitOptions? options)
    {
        if (options == null)
        {
            return false;
        }

        if (!AuthenticationRateLimitRuleValidator.IsValid(options.DefaultRule))
        {
            return false;
        }

        return options.ProviderRules.All(rule => IsProviderSelectorValid(rule.Key) && AuthenticationRateLimitRuleValidator.IsValid(rule.Value))
            && options.ExcludedProviders.All(IsProviderSelectorValid);
    }

    internal static bool IsProviderSelectorValid(string? selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return false;
        }

        if (selector != selector.Trim())
        {
            return false;
        }

        var separator = selector.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator >= selector.Length - 1)
        {
            return false;
        }

        var type = selector[..separator];
        var name = selector[(separator + 1)..];
        return !string.IsNullOrWhiteSpace(type)
            && !string.IsNullOrWhiteSpace(name)
            && type == type.Trim()
            && name == name.Trim();
    }
}
