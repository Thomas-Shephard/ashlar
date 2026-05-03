using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed class EmailCodeSignInOptions
{
    public int CodeLength { get; set; } = 6;
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    public string EmailSubject { get; set; } = "Your sign-in code";
    public string EmailTextTemplate { get; set; } = "Your sign-in code is {0}. It expires in {1} minutes.";
}
