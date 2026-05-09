namespace Ashlar.Identity.Models;

public sealed class EmailVerificationOptions
{
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(24);
    public string Subject { get; set; } = "Verify your email address";
    public string? FromAddress { get; set; }
}

public sealed class EmailVerificationRequest
{
    public required Guid UserId { get; init; }
}

public sealed class EmailVerificationResult
{
    public bool Succeeded { get; private init; }
    public string? ErrorMessage { get; private init; }

    public static EmailVerificationResult Success() => new() { Succeeded = true };
    public static EmailVerificationResult Failure(string errorMessage) => new() { Succeeded = false, ErrorMessage = errorMessage };
}
