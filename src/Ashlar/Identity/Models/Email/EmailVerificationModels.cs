using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Email;

/// <summary>
/// Configures email verification token lifetime, throttling, and message content.
/// </summary>
public sealed class EmailVerificationOptions
{
    /// <summary>
    /// Lifetime of the raw verification token.
    /// </summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(24);
    /// <summary>
    /// Rate limit applied when requesting verification messages.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromHours(1) };
    /// <summary>
    /// Rate limit applied when confirming verification tokens.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Subject used for verification emails.
    /// </summary>
    public string Subject { get; set; } = "Verify your email address";
    /// <summary>
    /// Plain-text message template. The first placeholder receives the callback URL containing the raw token.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to verify your email address: {0}";
    /// <summary>
    /// Optional sender address for verification emails.
    /// </summary>
    public string? FromAddress { get; set; }
    /// <summary>
    /// Query string parameter name used for the raw verification token.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";
    /// <summary>
    /// Query string parameter name used for the user identifier.
    /// </summary>
    public string UserIdParameterName { get; set; } = "u";

    /// <summary>
    /// Validates email verification options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(EmailVerificationOptions? options)
    {
        return options is { RequestRateLimit: { }, VerificationRateLimit: { } }
            && options.Expiration > TimeSpan.Zero
            && AuthenticationRateLimitRuleValidator.IsValid(options.RequestRateLimit)
            && AuthenticationRateLimitRuleValidator.IsValid(options.VerificationRateLimit)
            && !string.IsNullOrWhiteSpace(options.Subject)
            && !string.IsNullOrWhiteSpace(options.EmailTextTemplate)
            && !string.IsNullOrWhiteSpace(options.TokenParameterName)
            && !string.IsNullOrWhiteSpace(options.UserIdParameterName);
    }
}

/// <summary>
/// Request to send or enqueue an email verification message.
/// </summary>
public sealed class EmailVerificationRequest
{
    /// <summary>
    /// User whose email address should be verified.
    /// </summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// Base URI used to build the callback URL.
    /// </summary>
    /// <remarks>
    /// The service validates this URI with <see cref="Ashlar.Identity.Abstractions.Services.IUriValidator"/> before it appends the raw token.
    /// </remarks>
    public required Uri CallbackBaseUri { get; init; }
    /// <summary>
    /// Audit context to include in emitted security events.
    /// </summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to confirm an email verification token.
/// </summary>
public sealed class ConfirmEmailVerificationRequest
{
    /// <summary>
    /// User associated with the verification token.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Raw verification token from the callback URL. Do not log or persist this value.
    /// </summary>
    public required string? Token { get; init; }
    /// <summary>
    /// Audit context to include in emitted security events.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
