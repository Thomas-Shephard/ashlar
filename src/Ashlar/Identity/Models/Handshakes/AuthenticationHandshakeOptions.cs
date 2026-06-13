using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Configures handshake lifetime and verification throttling.
/// </summary>
public sealed class AuthenticationHandshakeOptions
{
    /// <summary>
    /// Lifetime of an issued handshake token.
    /// </summary>
    public TimeSpan Expiry { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Rate-limit rule applied to handshake verification attempts.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(1)
    };

    /// <summary>
    /// Validates authentication handshake options.
    /// </summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(AuthenticationHandshakeOptions? options)
    {
        return options is { VerificationRateLimit: { } }
            && options.Expiry > TimeSpan.Zero
            && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit);
    }
}
