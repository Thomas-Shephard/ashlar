using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Email;

/// <summary>
/// Configures email change token lifetime, throttling, message content, and session revocation.
/// </summary>
public sealed class EmailChangeOptions
{
    /// <summary>
    /// Lifetime of the raw email change token.
    /// </summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    /// <summary>
    /// Rate limit applied when requesting email change messages.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromHours(1) };
    /// <summary>
    /// Rate limit applied when confirming email change tokens.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Subject used for email change confirmation messages.
    /// </summary>
    public string Subject { get; set; } = "Confirm your new email address";
    /// <summary>
    /// Plain-text message template. The first placeholder receives the callback URL containing the raw token.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to confirm your new email address: {0}";
    /// <summary>
    /// Optional sender address for email change messages.
    /// </summary>
    public string? FromAddress { get; set; }
    /// <summary>
    /// Whether existing sessions are revoked after the email change is confirmed.
    /// </summary>
    public bool RevokeSessions { get; set; } = true;
    /// <summary>
    /// Query string parameter name used for the raw email change token.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";
    /// <summary>
    /// Query string parameter name used for the user identifier.
    /// </summary>
    public string UserIdParameterName { get; set; } = "u";

    /// <summary>
    /// Validates email change options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(EmailChangeOptions? options)
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
/// Request to send or enqueue an email change confirmation message.
/// </summary>
public sealed class RequestEmailChangeRequest
{
    /// <summary>
    /// User whose email address should be changed.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// New email address to confirm before it replaces the current address.
    /// </summary>
    public required string NewEmail { get; init; }

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
/// Request to confirm an email change token.
/// </summary>
public sealed class ConfirmEmailChangeRequest
{
    /// <summary>
    /// User associated with the email change token.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Raw email change token from the callback URL. Do not log or persist this value.
    /// </summary>
    public required string? Token { get; init; }
    /// <summary>
    /// Audit context to include in emitted security events.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
