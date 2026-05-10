namespace Ashlar.Identity.Models;

public sealed class EmailChangeOptions
{
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    public string Subject { get; set; } = "Confirm your new email address";
    public string EmailTextTemplate { get; set; } = "Click the following link to confirm your new email address: {0}";
    public string? FromAddress { get; set; }
    public bool RevokeSessions { get; set; } = true;
    public string TokenParameterName { get; set; } = "t";
    public string UserIdParameterName { get; set; } = "u";
}

public sealed class RequestEmailChangeRequest
{
    public required Guid UserId { get; init; }
    public required string NewEmail { get; init; }

    /// <summary>
    /// The base URI for the callback. This value is validated against a trusted allowlist to prevent Open Redirect and Phishing attacks.
    /// </summary>
    /// <remarks>
    /// WARNING: This URI must be validated using <see cref="Ashlar.Identity.Abstractions.IUriValidator"/> before use.
    /// </remarks>
    public required Uri CallbackBaseUri { get; init; }
    public AuthenticationContext? Context { get; init; }
}

public sealed class ConfirmEmailChangeRequest
{
    public required Guid UserId { get; init; }
    public required string Token { get; init; }
}

public sealed class EmailChangeResult
{
    public bool Succeeded { get; private init; }
    public string? ErrorMessage { get; private init; }

    public static EmailChangeResult Success() => new() { Succeeded = true };
    public static EmailChangeResult Failure(string errorMessage) => new() { Succeeded = false, ErrorMessage = errorMessage };
}
