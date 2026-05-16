namespace Ashlar.Identity.Models;

public sealed class EmailVerificationOptions
{
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(24);
    public string Subject { get; set; } = "Verify your email address";
    public string EmailTextTemplate { get; set; } = "Click the following link to verify your email address: {0}";
    public string? FromAddress { get; set; }
    public string TokenParameterName { get; set; } = "t";
    public string UserIdParameterName { get; set; } = "u";
}

public sealed class EmailVerificationRequest
{
    public required Guid UserId { get; init; }

    /// <summary>
    /// The base URI for the callback. This value is validated against a trusted allowlist to prevent Open Redirect and Phishing attacks.
    /// </summary>
    /// <remarks>
    /// WARNING: This URI must be validated using <see cref="Ashlar.Identity.Abstractions.IUriValidator"/> before use.
    /// </remarks>
    public required Uri CallbackBaseUri { get; init; }
    public AuthenticationContext? Context { get; init; }
}
