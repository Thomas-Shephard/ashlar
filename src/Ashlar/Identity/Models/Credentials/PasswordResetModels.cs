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
    /// Gets or sets the reset token lifetime.
    /// </summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    /// <summary>
    /// Gets or sets the request rate limit.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromHours(1) };
    /// <summary>
    /// Gets or sets the reset verification rate limit.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Gets or sets the reset email subject.
    /// </summary>
    public string Subject { get; set; } = "Reset your password";
    /// <summary>
    /// Gets or sets the reset email body template. The first placeholder receives the callback URL.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to reset your password: {0}";
    /// <summary>
    /// Gets or sets the from address.
    /// </summary>
    public string? FromAddress { get; set; }
    /// <summary>
    /// Gets or sets the reset token query parameter name.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";
    /// <summary>
    /// Gets or sets whether existing sessions are revoked after a successful password reset.
    /// </summary>
    public bool RevokeSessions { get; set; } = true;
    /// <summary>
    /// Gets or sets the minimum externally visible duration for generic reset request outcomes.
    /// </summary>
    public TimeSpan MinimumRequestDuration { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Validates password reset options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
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
    /// Gets or sets the one-time reset token.
    /// </summary>
    public required string Token { get; init; }
    /// <summary>
    /// Gets or sets the replacement password.
    /// </summary>
    public required string NewPassword { get; init; }
}

/// <summary>
/// Describes the result of a completed password reset.
/// </summary>
/// <param name="UserId">The user whose password was reset.</param>
/// <param name="SessionsRevoked">The number of sessions revoked after reset.</param>
public sealed record PasswordResetResult(Guid UserId, int SessionsRevoked);
