using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models;

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
    /// Executes the new operation.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(1)
    };
}
