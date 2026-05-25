using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides magic link sign in options behavior.
/// </summary>
public sealed class MagicLinkSignInOptions
{
    /// <summary>
    /// Gets or sets the link lifetime value.
    /// </summary>
    public TimeSpan LinkLifetime { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    /// <param name="PermitLimit">The permit limit value.</param>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    /// <param name="PermitLimit">The permit limit value.</param>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 30, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Gets or sets the email subject value.
    /// </summary>
    public string EmailSubject { get; set; } = "Sign in to our application";
    /// <summary>
    /// Gets or sets the email text template value.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to sign in: {0}";
    /// <summary>
    /// Gets or sets the link token parameter name value.
    /// </summary>
    public string LinkTokenParameterName { get; set; } = "token";

    /// <summary>
    /// Validates magic-link sign-in options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(MagicLinkSignInOptions? options)
    {
        return options is
        {
            RequestRateLimit.PermitLimit: > 0,
            VerificationRateLimit.PermitLimit: > 0
        }
        && options.LinkLifetime > TimeSpan.Zero
        && options.RequestRateLimit.Window > TimeSpan.Zero
        && options.VerificationRateLimit.Window > TimeSpan.Zero
        && !string.IsNullOrWhiteSpace(options.EmailSubject)
        && !string.IsNullOrWhiteSpace(options.EmailTextTemplate)
        && !string.IsNullOrWhiteSpace(options.LinkTokenParameterName);
    }
}
