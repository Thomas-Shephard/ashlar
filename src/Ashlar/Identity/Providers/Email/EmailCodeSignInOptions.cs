using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.RateLimiting;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Configures email-code sign-in issuance, delivery, and verification limits.
/// </summary>
public sealed class EmailCodeSignInOptions
{
    /// <summary>
    /// Minimum supported email code length.
    /// </summary>
    public const int MinimumCodeLength = 1;
    /// <summary>
    /// Maximum supported email code length.
    /// </summary>
    public const int MaximumCodeLength = 9;

    /// <summary>
    /// Number of digits generated for sign-in codes.
    /// </summary>
    public int CodeLength { get; set; } = 6;
    /// <summary>
    /// Lifetime of an issued sign-in code.
    /// </summary>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>
    /// Rate-limit rule for code requests.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    /// <summary>
    /// Rate-limit rule for code verification attempts.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    /// <summary>
    /// Subject for sign-in code emails.
    /// </summary>
    public string EmailSubject { get; set; } = "Your sign-in code";
    /// <summary>
    /// Plain-text template for sign-in code emails.
    /// The first placeholder receives the live code and the second receives the lifetime in minutes.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Your sign-in code is {0}. It expires in {1} minutes.";

    /// <summary>
    /// Validates email code sign-in options.
    /// </summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when sign-in codes can be issued and verified with the supplied settings.</returns>
    public static bool Validate(EmailCodeSignInOptions? options)
    {
        return options is
        {
            CodeLength: >= MinimumCodeLength and <= MaximumCodeLength,
            RequestRateLimit: { },
            VerificationRateLimit: { }
        }
        && options.CodeLifetime > TimeSpan.Zero
        && AuthenticationRateLimitRuleValidator.IsValid(options.RequestRateLimit)
        && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit)
        && !string.IsNullOrWhiteSpace(options.EmailSubject)
        && !string.IsNullOrWhiteSpace(options.EmailTextTemplate);
    }
}
