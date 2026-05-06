using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models;

public sealed class AuthenticationHandshakeOptions
{
    public TimeSpan Expiry { get; set; } = TimeSpan.FromMinutes(15);

    public RateLimitRule VerificationRateLimit { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(1)
    };
}
