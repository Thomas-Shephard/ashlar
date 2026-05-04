using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkSignInOptions
{
    public TimeSpan LinkLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromMinutes(15) };
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 30, Window = TimeSpan.FromMinutes(15) };
    public string EmailSubject { get; set; } = "Sign in to our application";
    public string EmailTextTemplate { get; set; } = "Click the following link to sign in: {0}";
    public string LinkTokenParameterName { get; set; } = "token";
}
