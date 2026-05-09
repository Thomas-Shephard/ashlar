namespace Ashlar.Identity.Models;

public sealed class BootstrapInvitationResult
{
    public required bool Succeeded { get; init; }
    public string? Token { get; init; }
    public string? FailureReason { get; init; }

    public static BootstrapInvitationResult Success(string token) => new() { Succeeded = true, Token = token };
    public static BootstrapInvitationResult Failure(string reason) => new() { Succeeded = false, FailureReason = reason };
}
