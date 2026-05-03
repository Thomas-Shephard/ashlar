using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkSignInOptions
{
    public TimeSpan LinkLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromMinutes(15), BlockDuration = TimeSpan.FromMinutes(15) };
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15), BlockDuration = TimeSpan.FromMinutes(15) };
    public string EmailSubject { get; set; } = "Sign in to Ashlar";
    public string EmailTextTemplate { get; set; } = "Click the link below to sign in:\n\n{0}\n\nThis link will expire in {1} minutes.";
    public string? EmailHtmlTemplate { get; set; }
    public string LinkTokenParameterName { get; set; } = "token";
    public string EmailParameterName { get; set; } = "email";
}
