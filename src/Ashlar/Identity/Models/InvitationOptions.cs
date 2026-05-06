using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models;

public sealed class InvitationOptions
{
    public TimeSpan DefaultExpiry { get; set; } = TimeSpan.FromDays(7);
    public string EmailSubject { get; set; } = "Invitation to join";
    public string EmailTextTemplate { get; set; } = "You have been invited. Use this link to join: {0}";

    public RateLimitRule CreationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    public RateLimitRule AcceptanceRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
}
