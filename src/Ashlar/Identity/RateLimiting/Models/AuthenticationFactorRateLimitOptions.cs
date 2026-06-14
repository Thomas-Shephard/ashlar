namespace Ashlar.Identity.RateLimiting.Models;

/// <summary>
/// Configures provider-neutral secondary factor verification rate limiting.
/// </summary>
public sealed class AuthenticationFactorRateLimitOptions : AuthenticationRateLimitOptions
{
    /// <summary>
    /// Default rule applied to secondary factor verification attempts.
    /// </summary>
    public override RateLimitRule DefaultRule { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(5),
        BlockDuration = TimeSpan.FromMinutes(5)
    };

    /// <summary>
    /// Validates secondary factor rate-limit options.
    /// </summary>
    /// <param name="options">Secondary factor rate-limit settings to validate.</param>
    /// <returns><see langword="true" /> when factor verification attempts can use the supplied settings.</returns>
    public static bool Validate(AuthenticationFactorRateLimitOptions? options)
    {
        return ValidateCore(options);
    }
}
