namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Configures provider-neutral primary authentication rate limiting.
/// </summary>
public sealed class PrimaryAuthenticationRateLimitOptions : AuthenticationRateLimitOptions
{
    /// <summary>
    /// Default rule applied to primary authentication attempts.
    /// </summary>
    public override RateLimitRule DefaultRule { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(10),
        BlockDuration = TimeSpan.FromMinutes(10)
    };

    /// <summary>
    /// Validates primary authentication rate-limit options.
    /// </summary>
    /// <param name="options">Primary authentication rate-limit settings to validate.</param>
    /// <returns><see langword="true" /> when primary authentication attempts can use the supplied settings.</returns>
    public static bool Validate(PrimaryAuthenticationRateLimitOptions? options)
    {
        return ValidateCore(options);
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
