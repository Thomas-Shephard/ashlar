using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.RateLimiting;

namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Configures invitation token lifetime, throttling, and message content.
/// </summary>
public sealed class InvitationOptions
{
    /// <summary>
    /// Default lifetime for newly created invitation tokens.
    /// </summary>
    public TimeSpan DefaultExpiry { get; set; } = TimeSpan.FromDays(7);
    /// <summary>
    /// Subject used for invitation emails.
    /// </summary>
    public string EmailSubject { get; set; } = "Invitation to join";
    /// <summary>
    /// Plain-text message template. The first placeholder receives the acceptance URL containing the raw token.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "You have been invited. Use this link to join: {0}";

    /// <summary>
    /// Rate-limit rule for creating invitations.
    /// </summary>
    public RateLimitRule CreationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Rate-limit rule for previewing invitations before acceptance.
    /// </summary>
    public RateLimitRule PreviewRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Rate-limit rule for accepting invitations.
    /// </summary>
    public RateLimitRule AcceptanceRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };

    /// <summary>
    /// Query string parameter name used for the raw invitation token.
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

    /// <summary>
    /// Validates invitation options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(InvitationOptions? options)
    {
        return options is { CreationRateLimit: { }, PreviewRateLimit: { }, AcceptanceRateLimit: { } }
            && options.DefaultExpiry > TimeSpan.Zero
            && AuthenticationRateLimitRuleValidator.IsValid(options.CreationRateLimit)
            && AuthenticationRateLimitRuleValidator.IsValid(options.PreviewRateLimit)
            && AuthenticationRateLimitRuleValidator.IsValid(options.AcceptanceRateLimit)
            && !string.IsNullOrWhiteSpace(options.EmailSubject)
            && !string.IsNullOrWhiteSpace(options.EmailTextTemplate)
            && !string.IsNullOrWhiteSpace(options.TokenParameterName);
    }
}
