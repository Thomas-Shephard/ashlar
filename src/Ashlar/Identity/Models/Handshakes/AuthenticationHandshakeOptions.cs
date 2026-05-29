using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Provides authentication handshake options behavior.
/// </summary>
public sealed class AuthenticationHandshakeOptions
{
    /// <summary>
    /// Gets or sets the expiry value.
    /// </summary>
    public TimeSpan Expiry { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the rate-limit rule applied to handshake verification attempts.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(1)
    };

    /// <summary>
    /// Validates authentication handshake options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(AuthenticationHandshakeOptions? options)
    {
        return options is { VerificationRateLimit: { } }
            && options.Expiry > TimeSpan.Zero
            && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit);
    }
}
