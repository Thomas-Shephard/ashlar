using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Provides invitation options behavior.
/// </summary>
public sealed class InvitationOptions
{
    /// <summary>
    /// Gets or sets the default expiry value.
    /// </summary>
    public TimeSpan DefaultExpiry { get; set; } = TimeSpan.FromDays(7);
    /// <summary>
    /// Gets or sets the email subject value.
    /// </summary>
    public string EmailSubject { get; set; } = "Invitation to join";
    /// <summary>
    /// Gets or sets the email text template value.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "You have been invited. Use this link to join: {0}";

    /// <summary>
    /// Gets or sets the rate limit rule for creating invitations.
    /// </summary>
    public RateLimitRule CreationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Gets or sets the rate limit rule for previewing invitations before acceptance.
    /// </summary>
    public RateLimitRule PreviewRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Gets or sets the rate limit rule for accepting invitations.
    /// </summary>
    public RateLimitRule AcceptanceRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };

    /// <summary>
    /// Gets or sets the token parameter name value.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";

    /// <summary>
    /// Whether to include the user's email address in invitation-related security audit events.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool StoreEmailInAudit { get; set; } = true;

    /// <summary>
    /// Whether to automatically mark the user's email as verified when they accept an invitation.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool VerifyEmailOnAcceptance { get; set; } = true;
}
