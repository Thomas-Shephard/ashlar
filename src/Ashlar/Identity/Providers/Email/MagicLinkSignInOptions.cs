using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.RateLimiting;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Configures magic-link sign-in issuance, delivery, and verification limits.
/// </summary>
public sealed class MagicLinkSignInOptions
{
    /// <summary>
    /// Lifetime of an issued magic-link token.
    /// </summary>
    public TimeSpan LinkLifetime { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>
    /// Rate-limit rule for magic-link requests.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Rate-limit rule for magic-link verification attempts.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 30, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Subject for magic-link emails.
    /// </summary>
    public string EmailSubject { get; set; } = "Sign in to our application";
    /// <summary>
    /// Plain-text template for magic-link emails.
    /// The first placeholder receives the callback URL containing the live token.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to sign in: {0}";
    /// <summary>
    /// Callback query parameter name that carries the live token.
    /// </summary>
    public string LinkTokenParameterName { get; set; } = "token";

    /// <summary>
    /// Validates magic-link sign-in options.
    /// </summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when magic links can be issued and verified with the supplied settings.</returns>
    public static bool Validate(MagicLinkSignInOptions? options)
    {
        return options is
        {
            RequestRateLimit: { },
            VerificationRateLimit: { }
        }
        && options.LinkLifetime > TimeSpan.Zero
        && AuthenticationRateLimitRuleValidator.IsValid(options.RequestRateLimit)
        && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit)
        && !string.IsNullOrWhiteSpace(options.EmailSubject)
        && !string.IsNullOrWhiteSpace(options.EmailTextTemplate)
        && !string.IsNullOrWhiteSpace(options.LinkTokenParameterName);
    }
}
