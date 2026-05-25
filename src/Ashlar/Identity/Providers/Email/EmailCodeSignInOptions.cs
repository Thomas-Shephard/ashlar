using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides email code sign in options behavior.
/// </summary>
public sealed class EmailCodeSignInOptions
{
    /// <summary>
    /// The minimum supported email code length.
    /// </summary>
    public const int MinimumCodeLength = 1;
    /// <summary>
    /// The maximum supported email code length.
    /// </summary>
    public const int MaximumCodeLength = 9;

    /// <summary>
    /// Gets or sets the code length value. Supported values are 1 through 9 digits.
    /// </summary>
    public int CodeLength { get; set; } = 6;
    /// <summary>
    /// Gets or sets the code lifetime value.
    /// </summary>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    /// <param name="PermitLimit">The permit limit value.</param>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    /// <param name="PermitLimit">The permit limit value.</param>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), BlockDuration = TimeSpan.FromMinutes(10) };
    /// <summary>
    /// Gets or sets the email subject value.
    /// </summary>
    public string EmailSubject { get; set; } = "Your sign-in code";
    /// <summary>
    /// Gets or sets the email text template value.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Your sign-in code is {0}. It expires in {1} minutes.";

    /// <summary>
    /// Validates email code sign-in options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(EmailCodeSignInOptions? options)
    {
        return options is
        {
            CodeLength: >= MinimumCodeLength and <= MaximumCodeLength,
            RequestRateLimit.PermitLimit: > 0,
            VerificationRateLimit.PermitLimit: > 0
        }
        && options.CodeLifetime > TimeSpan.Zero
        && options.RequestRateLimit.Window > TimeSpan.Zero
        && options.VerificationRateLimit.Window > TimeSpan.Zero
        && !string.IsNullOrWhiteSpace(options.EmailSubject)
        && !string.IsNullOrWhiteSpace(options.EmailTextTemplate);
    }
}
