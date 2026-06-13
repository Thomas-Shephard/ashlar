using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.RateLimiting;

namespace Ashlar.Identity.Models.Credentials;

/// <summary>
/// Configures local password reset behavior.
/// </summary>
public sealed class PasswordResetOptions
{
    private static readonly TimeSpan MaximumMinimumRequestDuration = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Lifetime of an issued password reset token.
    /// </summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    /// <summary>
    /// Rate-limit rule for password reset requests.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromHours(1) };
    /// <summary>
    /// Rate-limit rule for password reset verification attempts.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Subject for password reset emails.
    /// </summary>
    public string Subject { get; set; } = "Reset your password";
    /// <summary>
    /// Plain-text password reset email template. The first placeholder receives the callback URL.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to reset your password: {0}";
    /// <summary>
    /// Optional sender address for password reset emails.
    /// </summary>
    public string? FromAddress { get; set; }
    /// <summary>
    /// Query string parameter name used for the raw reset token.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";
    /// <summary>
    /// Whether existing sessions are revoked after a successful password reset.
    /// </summary>
    public bool RevokeSessions { get; set; } = true;
    /// <summary>
    /// Minimum externally visible duration for generic reset request outcomes.
    /// </summary>
    public TimeSpan MinimumRequestDuration { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Validates password reset options.
    /// </summary>
    /// <param name="options">Password reset settings to validate.</param>
    /// <returns><see langword="true" /> when reset requests and completions can use the supplied settings.</returns>
    public static bool Validate(PasswordResetOptions options)
    {
        return options is { RequestRateLimit: { }, VerificationRateLimit: { } }
        && options.Expiration > TimeSpan.Zero
        && AuthenticationRateLimitRuleValidator.IsValid(options.RequestRateLimit)
        && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit)
        && options.MinimumRequestDuration >= TimeSpan.Zero
        && options.MinimumRequestDuration <= MaximumMinimumRequestDuration
        && !string.IsNullOrWhiteSpace(options.Subject)
        && !string.IsNullOrWhiteSpace(options.EmailTextTemplate)
        && !string.IsNullOrWhiteSpace(options.TokenParameterName);
    }
}

/// <summary>
/// Describes a password reset completion request.
/// </summary>
public sealed class PasswordResetRequest
{
    /// <summary>
    /// One-time reset token from the callback URL. Do not log or persist this value.
    /// </summary>
    public required string? Token { get; init; }
    /// <summary>
    /// Replacement password supplied by the user. Do not log this value.
    /// </summary>
    public required string NewPassword { get; init; }
}

/// <summary>
/// Describes the result of a completed password reset.
/// </summary>
/// <param name="UserId">The user whose password was reset.</param>
/// <param name="SessionsRevoked">The number of sessions revoked after reset.</param>
public sealed record PasswordResetResult(Guid UserId, int SessionsRevoked);
