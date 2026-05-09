namespace Ashlar.Identity.Models;

public sealed class EmailChangeOptions
{
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(2);
    public string Subject { get; set; } = "Confirm your new email address";
    public string? FromAddress { get; set; }
    public bool RevokeSessions { get; set; } = true;
}

public sealed class RequestEmailChangeRequest
{
    public required Guid UserId { get; init; }
    public required string NewEmail { get; init; }
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
