using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Email;

/// <summary>
/// Provides email change options behavior.
/// </summary>
public sealed class EmailChangeOptions
{
    /// <summary>
    /// Gets or sets the expiration value.
    /// </summary>
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    /// <summary>
    /// Gets or sets the email change request rate limit.
    /// </summary>
    public RateLimitRule RequestRateLimit { get; set; } = new() { PermitLimit = 3, Window = TimeSpan.FromHours(1) };
    /// <summary>
    /// Gets or sets the email change confirmation rate limit.
    /// </summary>
    public RateLimitRule VerificationRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };
    /// <summary>
    /// Gets or sets the subject value.
    /// </summary>
    public string Subject { get; set; } = "Confirm your new email address";
    /// <summary>
    /// Gets or sets the email text template value.
    /// </summary>
    public string EmailTextTemplate { get; set; } = "Click the following link to confirm your new email address: {0}";
    /// <summary>
    /// Gets or sets the from address value.
    /// </summary>
    public string? FromAddress { get; set; }
    /// <summary>
    /// Gets or sets the revoke sessions value.
    /// </summary>
    public bool RevokeSessions { get; set; } = true;
    /// <summary>
    /// Gets or sets the token parameter name value.
    /// </summary>
    public string TokenParameterName { get; set; } = "t";
    /// <summary>
    /// Gets or sets the user id parameter name value.
    /// </summary>
    public string UserIdParameterName { get; set; } = "u";

    /// <summary>
    /// Validates email change options.
    /// </summary>
    /// <param name="options">The options value.</param>
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
/// Provides request email change request behavior.
/// </summary>
public sealed class RequestEmailChangeRequest
{
    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Gets or sets the new email value.
    /// </summary>
    public required string NewEmail { get; init; }

    /// <summary>
    /// The base URI for the callback. This value is validated against a trusted allowlist to prevent Open Redirect and Phishing attacks.
    /// </summary>
    /// <remarks>
    /// WARNING: This URI must be validated using <see cref="Ashlar.Identity.Abstractions.Services.IUriValidator"/> before use.
    /// </remarks>
    public required Uri CallbackBaseUri { get; init; }
    /// <summary>
    /// Gets or sets audit metadata for the request.
    /// </summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Provides confirm email change request behavior.
/// </summary>
public sealed class ConfirmEmailChangeRequest
{
    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Gets or sets the token value.
    /// </summary>
    public required string? Token { get; init; }
    /// <summary>
    /// Gets or sets audit metadata for the request.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
